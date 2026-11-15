//! Password acquisition.
//!
//! Mirrors sshpass: `-p`, `-e` (`SSHPASS`), `-f` (first line of a file),
//! `-d` (file descriptor; on Windows only 0/stdin is meaningful) and the
//! default "first line of stdin" mode.
//!
//! The stdin reader is intentionally byte-oriented and unbuffered so that
//! bytes after the first newline stay in the pipe for the child process.
//! That matters when callers do `printf 'pw\npayload\n' | sshpass ssh ...`.

use crate::cli::PasswordSource;
use crate::secret::Secret;
use std::fs::File;
use std::io::{BufRead, BufReader};
#[cfg(not(windows))]
use std::io::{self, Read};
use std::path::Path;

const MAX_PASSWORD_BYTES: usize = 64 * 1024;

pub fn resolve(source: &PasswordSource) -> Result<Secret, String> {
    match source {
        PasswordSource::Arg(value) => {
            if value.len() > MAX_PASSWORD_BYTES {
                return Err("password is too long".to_string());
            }
            Ok(Secret::new(value.clone()))
        }
        PasswordSource::Env => match std::env::var("SSHPASS") {
            Ok(value) => Ok(Secret::new(value)),
            Err(std::env::VarError::NotPresent) => {
                Err("SSHPASS environment variable is not set (required by -e)".to_string())
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                Err("SSHPASS is not valid UTF-8".to_string())
            }
        },
        PasswordSource::File(path) => read_first_line_from_file(path),
        PasswordSource::Fd(0) => read_first_line_from_stdin(),
        PasswordSource::Fd(fd) => Err(format!(
            "file descriptor {fd} is not supported on Windows; use -d 0 for stdin, or -f/-p/-e"
        )),
        PasswordSource::Stdin => read_first_line_from_stdin(),
    }
}

pub fn describe(source: &PasswordSource) -> &'static str {
    match source {
        PasswordSource::Arg(_) => "-p argument",
        PasswordSource::Env => "SSHPASS",
        PasswordSource::File(_) => "password file",
        PasswordSource::Fd(0) | PasswordSource::Stdin => "stdin",
        PasswordSource::Fd(_) => "file descriptor",
    }
}

fn strip_line_ending(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn read_first_line_from_file(path: &Path) -> Result<Secret, String> {
    let file = File::open(path)
        .map_err(|err| format!("cannot open password file {}: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let read = reader
        .read_until(b'\n', &mut bytes)
        .map_err(|err| format!("cannot read password file {}: {err}", path.display()))?;
    if read > MAX_PASSWORD_BYTES {
        return Err(format!(
            "password file {} is too large",
            path.display()
        ));
    }
    Ok(Secret::new(strip_line_ending(bytes)))
}

pub fn read_first_line_from_stdin() -> Result<Secret, String> {
    read_stdin_line_raw().map(Secret::new)
}

#[cfg(windows)]
fn read_stdin_line_raw() -> Result<String, String> {
    use std::ffi::c_void;

    // GetStdHandle/ReadFile are intentionally declared directly: this keeps
    // the Windows API surface tiny and avoids pulling in windows-sys just for
    // two calls.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn ReadFile(
            handle: *mut c_void,
            buffer: *mut u8,
            to_read: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
    let invalid = (-1isize) as *mut c_void;

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == invalid {
        return Err("stdin is not available".to_string());
    }

    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let mut read: u32 = 0;
        let ok = unsafe { ReadFile(handle, byte.as_mut_ptr(), 1, &mut read, std::ptr::null_mut()) };
        if ok == 0 {
            // EOF or a broken pipe; treat both as end of input.
            break;
        }
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > MAX_PASSWORD_BYTES {
            return Err("password from stdin is too long".to_string());
        }
    }
    Ok(strip_line_ending(bytes))
}

#[cfg(not(windows))]
fn read_stdin_line_raw() -> Result<String, String> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match lock.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                bytes.push(byte[0]);
                if bytes.len() > MAX_PASSWORD_BYTES {
                    return Err("password from stdin is too long".to_string());
                }
            }
            Err(err) => return Err(format!("cannot read password from stdin: {err}")),
        }
    }
    Ok(strip_line_ending(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn strips_crlf_and_lf() {
        assert_eq!(strip_line_ending(b"secret\r\n".to_vec()), "secret");
        assert_eq!(strip_line_ending(b"secret\n".to_vec()), "secret");
        assert_eq!(strip_line_ending(b"secret".to_vec()), "secret");
        assert_eq!(strip_line_ending(b"secret\r\r\n".to_vec()), "secret");
        assert_eq!(strip_line_ending(b"\r\n".to_vec()), "");
    }

    #[test]
    fn reads_first_line_from_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("sshpass-rs-pw-{}.txt", std::process::id()));
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"first-line\r\nsecond-line\n").unwrap();
        }
        let secret = read_first_line_from_file(&path).unwrap();
        assert_eq!(secret.expose(), "first-line");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let path = std::env::temp_dir().join("sshpass-rs-does-not-exist-xyz");
        let err = read_first_line_from_file(&path).unwrap_err();
        assert!(err.contains("cannot open password file"), "{err}");
    }

    #[test]
    fn env_password() {
        // SAFETY: tests in this module are not run concurrently with each
        // other when using --test-threads=1; the key is unique to this test.
        std::env::set_var("SSHPASS", "from-env");
        let secret = resolve(&PasswordSource::Env).unwrap();
        assert_eq!(secret.expose(), "from-env");
        std::env::remove_var("SSHPASS");
    }

    #[test]
    fn unsupported_fd_is_an_error() {
        let err = resolve(&PasswordSource::Fd(3)).unwrap_err();
        assert!(err.contains("not supported on Windows"), "{err}");
    }
}
