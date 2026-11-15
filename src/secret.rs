//! A tiny zeroing wrapper for secrets.
//!
//! The password is held in a `String` for the lifetime of the process.  On
//! drop we overwrite the backing bytes so the value does not linger in the
//! allocator longer than necessary.  This is best-effort (the OS may have
//! copied the memory), but it avoids the most obvious accidental leaks.

use std::fmt;

pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: `as_bytes_mut` requires the contents to remain valid UTF-8.
        // Replacing every byte with 0 keeps the string valid (NUL is valid
        // UTF-8) and does not change its length.
        unsafe {
            for byte in self.0.as_bytes_mut() {
                *byte = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(secret.expose(), "hunter2");
    }

    #[test]
    fn empty_is_empty() {
        assert!(Secret::new(String::new()).is_empty());
    }
}
