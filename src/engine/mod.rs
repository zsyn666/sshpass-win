//! Engine selection and dispatch.

pub mod askpass;
pub mod pty;

use crate::cli::Cli;
use crate::secret::Secret;
use crate::which::ProgramInfo;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// OpenSSH's SSH_ASKPASS mechanism: no pty, stdout and stderr stay apart.
    Askpass,
    /// ConPTY relay with prompt detection: sshpass's original model.
    Pty,
}

/// Does ssh's argument list ask for a pseudo terminal?
///
/// `-t` and `-tt` force one; without it ssh derives the decision from its own
/// stdin, which the askpass engine leaves as the caller's handle. Detecting the
/// flag lets interactive callers get the pty they asked for.
fn wants_tty(args: &[std::ffi::OsString]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.to_str() else { continue };
        if text == "--" {
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        if text == "-t" || text == "-tt" {
            return true;
        }
        if let Some(flags) = text.strip_prefix('-') {
            for (index, flag) in flags.char_indices() {
                if flag == 't' {
                    return true;
                }
                if matches!(
                    flag,
                    'B' | 'b'
                        | 'c'
                        | 'D'
                        | 'E'
                        | 'e'
                        | 'F'
                        | 'I'
                        | 'i'
                        | 'J'
                        | 'L'
                        | 'l'
                        | 'm'
                        | 'O'
                        | 'o'
                        | 'P'
                        | 'p'
                        | 'Q'
                        | 'R'
                        | 'S'
                        | 'W'
                        | 'w'
                ) {
                    // This option consumes the rest of the token or the next
                    // argument; stop looking inside it.
                    if flags[index + flag.len_utf8()..].is_empty() {
                        iter.next();
                    }
                    break;
                }
            }
        }
    }
    false
}

pub fn choose(cli: &Cli, program: &ProgramInfo) -> Result<Engine, String> {
    if let Ok(forced) = std::env::var("SSHPASS_RS_ENGINE") {
        match forced.to_ascii_lowercase().as_str() {
            "askpass" => {
                if !program.is_openssh_family {
                    return Err(
                        "SSHPASS_RS_ENGINE=askpass requires an ssh/scp/sftp command".to_string()
                    );
                }
                return Ok(Engine::Askpass);
            }
            "pty" => {
                return Ok(Engine::Pty);
            }
            other => {
                return Err(format!(
                    "invalid SSHPASS_RS_ENGINE={other:?}; expected askpass or pty"
                ));
            }
        }
    }

    // sftp does not ask for a password when its stdin is not a terminal, even
    // with SSH_ASKPASS_REQUIRE=force. Original sshpass gives it a pty; so do we.
    if program.stem == "sftp" {
        return Ok(Engine::Pty);
    }

    // `ssh -t` / `ssh -tt` explicitly need a terminal for the remote side.
    if program.stem == "ssh" && wants_tty(&cli.args) {
        return Ok(Engine::Pty);
    }

    if program.is_openssh_family && !program.is_msys {
        return Ok(Engine::Askpass);
    }

    Ok(Engine::Pty)
}

pub fn run(
    engine: Engine,
    cli: &Cli,
    program: &Path,
    password: Arc<Secret>,
    verbose: bool,
) -> Result<i32, String> {
    match engine {
        Engine::Askpass => askpass::run(cli, program, password.as_ref(), verbose),
        Engine::Pty => pty::run(cli, program, password, verbose),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn detects_tty_flags() {
        assert!(wants_tty(&args(&["-t", "host"])));
        assert!(wants_tty(&args(&["-tt", "host"])));
        assert!(wants_tty(&args(&["-vt", "host"])));
        assert!(!wants_tty(&args(&["-T", "host"])));
        assert!(!wants_tty(&args(&[
            "-o",
            "StrictHostKeyChecking=no",
            "host"
        ])));
        assert!(!wants_tty(&args(&["host", "-t"])));
    }

    #[test]
    fn tty_option_that_takes_a_value_is_skipped() {
        assert!(!wants_tty(&args(&["-p", "22", "host"])));
        assert!(!wants_tty(&args(&["-o", "ConnectTimeout=5", "host"])));
    }
}
