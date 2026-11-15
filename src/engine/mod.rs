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
    /// OpenSSH's SSH_ASKPASS mechanism (no pty, most reliable).
    Askpass,
    /// ConPTY relay with prompt detection (arbitrary console programs).
    Pty,
}

pub fn choose(program: &ProgramInfo, verbose: bool) -> Result<Engine, String> {
    if let Ok(forced) = std::env::var("SSHPASS_RS_ENGINE") {
        match forced.to_ascii_lowercase().as_str() {
            "askpass" => {
                if !program.is_openssh_family {
                    return Err(
                        "SSHPASS_RS_ENGINE=askpass requires an ssh/scp/sftp command".to_string(),
                    );
                }
                let ssh = askpass::find_ssh(&program.path)
                    .ok_or_else(|| "cannot find ssh.exe for askpass".to_string())?;
                if !askpass::supports_askpass(&ssh) {
                    return Err(format!(
                        "{} does not support SSH_ASKPASS_REQUIRE (OpenSSH >= 8.4 required)",
                        ssh.display()
                    ));
                }
                if verbose {
                    eprintln!("sshpass: engine forced to askpass");
                }
                return Ok(Engine::Askpass);
            }
            "pty" => {
                if verbose {
                    eprintln!("sshpass: engine forced to pty");
                }
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
    // with SSH_ASKPASS_REQUIRE=force.  Original sshpass gives it a pty; do the
    // same so `sftp -b -` and interactive sftp both work.
    if program.stem == "sftp" {
        if verbose {
            eprintln!("sshpass: sftp selected; using the pty engine");
        }
        return Ok(Engine::Pty);
    }

    if program.is_openssh_family && !program.is_msys {
        if let Some(ssh) = askpass::find_ssh(&program.path) {
            if askpass::supports_askpass(&ssh) {
                return Ok(Engine::Askpass);
            }
            if verbose {
                eprintln!(
                    "sshpass: {} is older than 8.4; falling back to the pty engine",
                    ssh.display()
                );
            }
        }
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
