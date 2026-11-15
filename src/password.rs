//! Password acquisition.
//!
//! Mirrors sshpass: `-p`, `-e[env_var]`, `-f` (first line of a file),
//! `-d` (file descriptor; on Windows only stdin is meaningful) and the
//! default "first line of stdin" mode.
//!
//! The stdin reader is byte-oriented and unbuffered so bytes after the first
//! newline stay in the pipe for the child process. That matters when callers
//! do `printf 'pw\npayload\n' | sshpass ssh ...`.

use crate::cli::PasswordSource;
use crate::secret::Secret;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
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
        PasswordSource::Env(name) => match std::env::var(name) {
            Ok(value) => Ok(Secret::new(value)),
            Err(std::env::VarError::NotPresent) => Err(format!(
                "sshpass: -e option given but \"{name}\" environment variable is not set."
            )),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!(
                "environment variable \"{name}\" is not valid UTF-8"
            )),
        },
        PasswordSource::File(path) => read_first_line_from_file(path),
        PasswordSource::Fd(0) => read_first_line_from_stdin(),
        // Windows has no POSIX file descriptors. sshpass reads the descriptor
        // only when a prompt appears; an unreadable descriptor produces an
        // empty password and normal authentication failure. Do the same.
        PasswordSource::Fd(_) => Ok(Secret::new(String::new())),
        PasswordSource::Stdin => read_first_line_from_stdin(),
    }
}

fn strip_line_ending(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn read_first_line_from_file(path: &Path) -> Result<Secret, String> {
    let file = File::open(path).map_err(|err| {
        format!(
            "SSHPASS: Failed to open password file \"{}\": {err}",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file.take(MAX_PASSWORD_BYTES as u64 + 1));
    let mut bytes = Vec::new();
    reader.read_until(b'\n', &mut bytes).map_err(|err| {
        format!(
            "SSHPASS: Failed to read password file \"{}\": {err}",
            path.display()
        )
    })?;
    if bytes.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "SSHPASS: password file \"{}\" is too large",
            path.display()
        ));
    }
    Ok(Secret::new(strip_line_ending(bytes)))
}

pub fn read_first_line_from_stdin() -> Result<Secret, String> {
    read_stdin_line_raw().map(Secret::new)
}

#[cfg(not(windows))]
compile_error!("sshpass-win only builds for Windows");

#[cfg(windows)]
fn read_stdin_line_raw() -> Result<String, String> {
    use std::ffi::c_void;

    // GetStdHandle/ReadFile are declared directly: this keeps the API surface
    // tiny and avoids pulling in windows-sys just for two calls.
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
        let ok = unsafe {
            ReadFile(
                handle,
                byte.as_mut_ptr(),
                1,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
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
        path.push(format!("sshpass-win-pw-{}.txt", std::process::id()));
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
        let path = std::env::temp_dir().join("sshpass-win-does-not-exist-xyz");
        let err = read_first_line_from_file(&path).unwrap_err();
        assert!(err.contains("Failed to open password file"), "{err}");
    }

    #[test]
    fn huge_file_is_rejected_without_reading_it_all() {
        let path =
            std::env::temp_dir().join(format!("sshpass-win-huge-{}.txt", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len((MAX_PASSWORD_BYTES as u64) + 1024).unwrap();
        let err = read_first_line_from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn env_password() {
        std::env::set_var("SSHPASS_TEST_ENV_NAME", "from-env");
        let secret = resolve(&PasswordSource::Env("SSHPASS_TEST_ENV_NAME".into())).unwrap();
        assert_eq!(secret.expose(), "from-env");
        std::env::remove_var("SSHPASS_TEST_ENV_NAME");
    }

    #[test]
    fn missing_env_is_an_error() {
        let err = resolve(&PasswordSource::Env("SSHPASS_TEST_ENV_MISSING".into())).unwrap_err();
        assert!(err.contains("environment variable is not set"), "{err}");
    }

    #[test]
    fn other_fds_produce_an_empty_password() {
        let secret = resolve(&PasswordSource::Fd(3)).unwrap();
        assert_eq!(secret.expose(), "");
    }
}
