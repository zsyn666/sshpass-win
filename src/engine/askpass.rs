//! OpenSSH `SSH_ASKPASS` engine.
//!
//! OpenSSH can delegate password prompts to a helper program. This engine
//! points `SSH_ASKPASS` at this executable, so ssh asks us for the password
//! instead of a terminal. It keeps stdout/stderr separate and works without a
//! pseudo console.

use crate::cli::Cli;
use crate::prompt::{is_host_key_question, prompt_matches};
use crate::secret::Secret;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

pub const HELPER_ENV: &str = "SSHPASS_RS_ASKPASS";
pub const PASSWORD_ENV: &str = "SSHPASS_RS_PASSWORD";
pub const PROMPT_ENV: &str = "SSHPASS_RS_PROMPT";
pub const COUNT_ENV: &str = "SSHPASS_RS_PROMPT_COUNT";
pub const VERBOSE_ENV: &str = "SSHPASS_RS_VERBOSE";

pub fn is_helper_invocation() -> bool {
    std::env::var_os(HELPER_ENV).is_some_and(|value| value == "1")
}

/// Called when ssh invokes this executable as its askpass helper.
pub fn helper() -> ! {
    let verbose = std::env::var_os(VERBOSE_ENV).is_some();
    let mut previous = 0u64;
    if let Some(path) = std::env::var_os(COUNT_ENV) {
        if let Ok(metadata) = std::fs::metadata(&path) {
            previous = metadata.len();
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(b"1");
        }
    }

    let prompt = std::env::args_os()
        .nth(1)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();

    if is_host_key_question(&prompt) {
        eprintln!(
            "SSHPASS: refusing to answer a host-key confirmation prompt with a password: {prompt}"
        );
        eprintln!("SSHPASS: pre-add the host key or pass -o StrictHostKeyChecking=accept-new");
        std::process::exit(1);
    }

    let custom = std::env::var(PROMPT_ENV).unwrap_or_else(|_| crate::prompt::DEFAULT_PROMPT.into());
    if !prompt_matches(&prompt, &custom) {
        eprintln!("SSHPASS: prompt does not contain the -P value {custom:?}");
        std::process::exit(1);
    }

    if verbose {
        eprintln!("SSHPASS: read: {prompt}");
        if previous == 0 {
            eprintln!("SSHPASS: detected prompt. Sending password.");
        } else {
            eprintln!("SSHPASS: detected prompt, again. Wrong password. Terminating.");
        }
    }
    if previous > 0 {
        // sshpass terminates on the second prompt instead of trying again.
        std::process::exit(1);
    }

    let password = match std::env::var(PASSWORD_ENV) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("SSHPASS: internal askpass invocation without a password");
            std::process::exit(1);
        }
    };

    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(password.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    std::process::exit(0);
}

fn askpass_path() -> Result<OsString, String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("cannot determine the current executable: {err}"))?;
    let text = exe.to_string_lossy();
    let cleaned = text.strip_prefix(r"\\?\").unwrap_or(&text);
    Ok(OsString::from(cleaned))
}

fn count_path() -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "sshpass-win-{}-{}.count",
        std::process::id(),
        stamp
    ))
}

pub fn run(cli: &Cli, program: &Path, password: &Secret, verbose: bool) -> Result<i32, String> {
    let askpass = askpass_path()?;
    let counts = count_path();
    let _ = std::fs::remove_file(&counts);

    if verbose {
        eprintln!(
            "SSHPASS: searching for password prompt using match \"{}\"",
            cli.prompt
        );
    }

    let mut command = Command::new(program);
    command.args(&cli.args);
    command.env("SSH_ASKPASS", &askpass);
    command.env("SSH_ASKPASS_REQUIRE", "force");
    command.env(HELPER_ENV, "1");
    command.env(PASSWORD_ENV, password.expose());
    command.env(PROMPT_ENV, &cli.prompt);
    command.env(COUNT_ENV, &counts);
    if verbose {
        command.env(VERBOSE_ENV, "1");
    }
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|err| format!("SSHPASS: Failed to run command: {err}"))?;

    // Relay ssh's stderr while watching for the host-key message. ssh writes
    // that prompt to stderr, not to a tty, when it has no terminal.
    let mut stderr = child.stderr.take();
    let (stderr_tx, stderr_rx) = mpsc::channel::<bool>();
    if let Some(mut stream) = stderr.take() {
        thread::spawn(move || {
            let mut tail = String::new();
            let mut buffer = [0u8; 4096];
            let mut host_key_unknown = false;
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        let _ = std::io::stderr().write_all(&buffer[..count]);
                        let _ = std::io::stderr().flush();
                        tail.push_str(&String::from_utf8_lossy(&buffer[..count]));
                        if crate::prompt::is_host_key_prompt(&tail) {
                            host_key_unknown = true;
                        }
                        if tail.len() > 8192 {
                            tail.drain(..tail.len() - 8192);
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = stderr_tx.send(host_key_unknown);
        });
    } else {
        let _ = stderr_tx.send(false);
    }

    let status = child
        .wait()
        .map_err(|err| format!("SSHPASS: error while waiting for the child: {err}"))?;
    let host_key_unknown = stderr_rx.recv().unwrap_or(false);

    let prompt_count = std::fs::read_to_string(&counts)
        .map(|text| text.len())
        .unwrap_or(0);
    let _ = std::fs::remove_file(&counts);

    let mut code = status.code().unwrap_or(1);
    if code != 0 {
        if host_key_unknown {
            code = crate::exit::HOST_KEY_UNKNOWN;
        } else if prompt_count >= 2 {
            // sshpass treats a repeated password prompt as a wrong password.
            code = crate::exit::INCORRECT_PASSWORD;
        }
    }

    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_matching_uses_default_marker() {
        assert!(prompt_matches("root@host's password: ", "assword"));
        assert!(!prompt_matches("Verification code: ", "assword"));
    }
}
