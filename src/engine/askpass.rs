//! OpenSSH `SSH_ASKPASS` engine.
//!
//! Instead of driving a pty, this engine lets OpenSSH ask *us* for the
//! password.  It is the most reliable path on Windows and works under the
//! DSH file sandbox because no Cygwin/MSYS runtime and no named signal pipe
//! are involved.

use crate::cli::Cli;
use crate::prompt::{is_host_key_prompt, prompt_matches};
use crate::secret::Secret;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const HELPER_ENV: &str = "SSHPASS_RS_ASKPASS";
pub const PASSWORD_ENV: &str = "SSHPASS_RS_PASSWORD";
pub const PROMPT_ENV: &str = "SSHPASS_RS_PROMPT";

pub fn is_helper_invocation() -> bool {
    std::env::var_os(HELPER_ENV).is_some_and(|value| value == "1")
}

/// Called when ssh invokes this executable as its askpass helper.
pub fn helper() -> ! {
    let prompt = std::env::args_os()
        .nth(1)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();

    if is_host_key_prompt(&prompt) {
        eprintln!(
            "sshpass: refusing to answer a host-key confirmation prompt with a password: {prompt}"
        );
        eprintln!("sshpass: pre-add the host key or pass -o StrictHostKeyChecking=accept-new");
        std::process::exit(1);
    }

    let custom = std::env::var(PROMPT_ENV).ok();
    if let Some(custom) = custom.as_deref() {
        if !prompt.contains(custom) {
            eprintln!("sshpass: prompt does not contain the -P value {custom:?}");
            std::process::exit(1);
        }
    } else if !prompt_matches(&prompt, None) {
        eprintln!("sshpass: unrecognized password prompt: {prompt}");
        std::process::exit(1);
    }

    let password = match std::env::var(PASSWORD_ENV) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("sshpass: internal askpass invocation without a password");
            std::process::exit(1);
        }
    };

    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(password.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    std::process::exit(0);
}

/// Find the ssh binary that belongs to `program` (same directory for
/// scp/sftp, otherwise `ssh` from PATH).
pub fn find_ssh(program: &Path) -> Option<PathBuf> {
    let stem = program
        .file_stem()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if stem == "ssh" {
        return Some(program.to_path_buf());
    }
    if let Some(dir) = program.parent() {
        let candidate = dir.join("ssh.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    crate::which::resolve(std::ffi::OsStr::new("ssh"))
        .ok()
        .map(|info| info.path)
}

/// Parse `OpenSSH_for_Windows_9.5p2` / `OpenSSH_9.5p2`.
pub fn parse_openssh_version(text: &str) -> Option<(u32, u32)> {
    let start = text.find("OpenSSH")? + "OpenSSH".len();
    let bytes = text.as_bytes();
    let mut i = start;
    while i < bytes.len() && !bytes[i].is_ascii_digit() {
        i += 1;
    }
    let major_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == major_start {
        return None;
    }
    let major: u32 = text[major_start..i].parse().ok()?;
    if i >= bytes.len() || bytes[i] != b'.' {
        return Some((major, 0));
    }
    i += 1;
    let minor_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == minor_start {
        return Some((major, 0));
    }
    let minor: u32 = text[minor_start..i].parse().ok()?;
    Some((major, minor))
}

pub fn ssh_version(ssh: &Path) -> Option<(u32, u32)> {
    let output = Command::new(ssh)
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    parse_openssh_version(&text)
}

/// `SSH_ASKPASS_REQUIRE=force` was added in OpenSSH 8.4.
pub fn supports_askpass(ssh: &Path) -> bool {
    matches!(ssh_version(ssh), Some((major, minor)) if (major, minor) >= (8, 4))
}

fn askpass_path() -> Result<OsString, String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("cannot determine the current executable: {err}"))?;
    // CreateProcess accepts verbatim paths, but ssh's own path handling is
    // happier without the \\?\ prefix.
    let text = exe.to_string_lossy();
    let cleaned = text.strip_prefix(r"\\?\").unwrap_or(&text);
    Ok(OsString::from(cleaned))
}

pub fn run(
    cli: &Cli,
    program: &Path,
    password: &Secret,
    verbose: bool,
) -> Result<i32, String> {
    let askpass = askpass_path()?;

    if verbose {
        eprintln!("sshpass: engine: askpass");
        eprintln!("sshpass: askpass helper: {}", askpass.to_string_lossy());
    }

    let mut command = Command::new(program);
    command.args(&cli.args);
    command.env("SSH_ASKPASS", &askpass);
    command.env("SSH_ASKPASS_REQUIRE", "force");
    command.env(HELPER_ENV, "1");
    command.env(PASSWORD_ENV, password.expose());
    if let Some(prompt) = cli.prompt.as_deref() {
        command.env(PROMPT_ENV, prompt);
    }

    let status = command
        .status()
        .map_err(|err| format!("cannot start {}: {err}", program.display()))?;

    if verbose {
        match status.code() {
            Some(code) => eprintln!("sshpass: child exited with status {code}"),
            None => eprintln!("sshpass: child terminated without an exit code"),
        }
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_version() {
        assert_eq!(
            parse_openssh_version("OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2"),
            Some((9, 5))
        );
        assert_eq!(parse_openssh_version("OpenSSH_8.4p1 Debian"), Some((8, 4)));
        assert_eq!(parse_openssh_version("OpenSSH_9.5"), Some((9, 5)));
        assert_eq!(parse_openssh_version("something else"), None);
    }

    #[test]
    fn version_ordering() {
        assert!((8, 4) >= (8, 4));
        assert!((10, 0) > (9, 9));
    }

    #[test]
    fn real_ssh_version_is_recent() {
        if let Some((major, minor)) = ssh_version(Path::new(r"C:\Windows\System32\OpenSSH\ssh.exe")) {
            assert!((major, minor) >= (8, 4), "unexpected version {major}.{minor}");
        }
    }
}
