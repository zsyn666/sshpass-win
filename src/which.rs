//! Locate the program the caller asked us to run.
//!
//! We resolve it ourselves (instead of letting CreateProcess search PATH) so
//! that we can (a) print a useful path in `-v` output, (b) distinguish native
//! Windows OpenSSH from MSYS/Cygwin ssh, and (c) choose the right engine.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    pub path: PathBuf,
    /// Lower-case file stem (`ssh`, `scp`, `sftp`, ...).
    pub stem: String,
    /// Basename is ssh/scp/sftp.
    pub is_openssh_family: bool,
    /// Path lives in an MSYS2/Cygwin installation.
    pub is_msys: bool,
}

pub fn resolve(program: &OsStr) -> Result<ProgramInfo, String> {
    let raw = program.to_string_lossy();
    let path = if raw.contains('\\') || raw.contains('/') || Path::new(program).is_absolute() {
        let path = PathBuf::from(program);
        if !path.is_file() {
            return Err("No such file or directory".to_string());
        }
        path
    } else {
        find_in_path(program)?
    };

    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let lower_path = path.to_string_lossy().to_ascii_lowercase();

    Ok(ProgramInfo {
        is_openssh_family: matches!(stem.as_str(), "ssh" | "scp" | "sftp"),
        is_msys: lower_path.contains("\\msys64\\")
            || lower_path.contains("\\cygwin\\")
            || lower_path.contains("\\usr\\bin\\"),
        stem,
        path,
    })
}

fn find_in_path(program: &OsStr) -> Result<PathBuf, String> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();

    for dir in std::env::split_paths(&path_var) {
        let direct = dir.join(program);
        if direct.is_file() {
            return Ok(direct);
        }

        if Path::new(program).extension().is_none() {
            let with_exe = direct.with_extension("exe");
            if with_exe.is_file() {
                return Ok(with_exe);
            }
            let with_com = direct.with_extension("com");
            if with_com.is_file() {
                return Ok(with_com);
            }
        }
    }

    Err("No such file or directory".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_cmd() {
        let info = resolve(OsStr::new("cmd")).expect("cmd.exe should exist");
        assert!(info.path.is_file());
        assert!(!info.is_openssh_family);
    }

    #[test]
    fn resolves_ssh_when_present() {
        if let Ok(info) = resolve(OsStr::new("ssh")) {
            assert!(info.path.is_file());
            assert!(info.is_openssh_family);
            let lower = info.path.to_string_lossy().to_ascii_lowercase();
            if lower.contains("\\windows\\system32\\openssh\\") {
                assert!(!info.is_msys);
            }
        }
    }

    #[test]
    fn missing_program_is_an_error() {
        let err = resolve(OsStr::new("definitely-not-a-real-program-xyz")).unwrap_err();
        assert!(err.contains("No such file or directory"), "{err}");
    }

    #[test]
    fn absolute_missing_program_is_an_error() {
        let err = resolve(OsStr::new(r"C:\definitely\missing\sshpass-nope.exe")).unwrap_err();
        assert!(err.contains("No such file or directory"), "{err}");
    }
}
