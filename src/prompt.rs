//! Password-prompt detection.
//!
//! A pty stream contains ANSI escape sequences, carriage returns and screen
//! updates.  We keep a short rolling window of *printable* output and look for
//! sshpass's default marker (`assword`, which matches both `Password:` and
//! `password:`) or a caller-supplied `-P` string.

use std::time::{Duration, Instant};

const DEFAULT_MARKERS: [&str; 2] = ["assword", "passphrase"];
const TAIL_LIMIT: usize = 4096;
const MAX_SENDS: usize = 3;
const SEND_COOLDOWN: Duration = Duration::from_millis(400);

#[derive(Debug)]
pub struct PromptScanner {
    tail: String,
    custom: Option<String>,
    sends: usize,
    last_send: Option<Instant>,
}

impl PromptScanner {
    pub fn new(custom: Option<String>) -> Self {
        Self {
            tail: String::new(),
            custom,
            sends: 0,
            last_send: None,
        }
    }

    pub fn sends(&self) -> usize {
        self.sends
    }

    /// Feed output bytes.  Returns true exactly when the password should be
    /// written to the child.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        let text = strip_ansi(bytes);
        if text.is_empty() {
            return false;
        }
        self.tail.push_str(&text);
        if self.tail.len() > TAIL_LIMIT {
            let mut cut = self.tail.len() - TAIL_LIMIT;
            while cut < self.tail.len() && !self.tail.is_char_boundary(cut) {
                cut += 1;
            }
            self.tail.drain(..cut);
        }

        if self.sends >= MAX_SENDS {
            return false;
        }
        if let Some(last) = self.last_send {
            if last.elapsed() < SEND_COOLDOWN {
                return false;
            }
        }
        if !prompt_matches(&self.tail, self.custom.as_deref()) {
            return false;
        }

        self.sends += 1;
        self.last_send = Some(Instant::now());
        // The prompt has been answered; drop it so a later chunk that still
        // contains the old text does not cause a duplicate send.
        self.tail.clear();
        true
    }
}

pub fn prompt_matches(text: &str, custom: Option<&str>) -> bool {
    if let Some(custom) = custom {
        return text.contains(custom);
    }
    let lower = text.to_lowercase();
    DEFAULT_MARKERS.iter().any(|marker| lower.contains(marker))
}

pub fn is_host_key_prompt(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("yes/no")
        || lower.contains("continue connecting")
        || lower.contains("authenticity")
        || lower.contains("fingerprint")
}

/// Remove ConPTY's cursor-position query (`ESC [ 6 n`) from the output stream.
/// portable-pty asks for this query because it creates the pseudo console with
/// PSEUDOCONSOLE_INHERIT_CURSOR; we answer it internally, so it must not reach
/// the caller's terminal as literal garbage.
pub fn strip_cursor_query(bytes: &[u8]) -> Vec<u8> {
    let needle = b"\x1b[6n";
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Removes the password from output emitted after it was typed.
///
/// Real ssh reads a password with console echo disabled, but arbitrary console
/// programs may echo it.  Original sshpass disables ECHO on its pty; ConPTY has
/// no master-side termios, so we redact the exact password instead.  This is a
/// best-effort safety net; it also keeps `-v`/logs free of the secret.
pub struct Redactor {
    secret: Vec<u8>,
    active: bool,
    carry: Vec<u8>,
}

impl Redactor {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            active: false,
            carry: Vec::new(),
        }
    }

    pub fn activate(&mut self) {
        self.active = true;
    }

    pub fn filter(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.active || self.secret.is_empty() {
            return chunk.to_vec();
        }
        self.carry.extend_from_slice(chunk);

        // Hold back a trailing partial password so a password split across
        // reads is still removed as a unit.
        let mut keep = 0usize;
        for candidate in (1..self.secret.len().min(self.carry.len()) + 1).rev() {
            if self.carry[self.carry.len() - candidate..] == self.secret[..candidate] {
                keep = candidate;
                break;
            }
        }
        let process_len = self.carry.len() - keep;

        let mut out = Vec::with_capacity(process_len);
        let mut i = 0usize;
        while i < process_len {
            if i + self.secret.len() <= process_len
                && self.carry[i..i + self.secret.len()] == self.secret
            {
                i += self.secret.len();
            } else {
                out.push(self.carry[i]);
                i += 1;
            }
        }
        self.carry = self.carry[process_len..].to_vec();
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.carry)
    }
}


/// Remove ANSI CSI/OSC sequences so prompt matching is not confused by color
/// or cursor-control codes.  UTF-8 text is preserved byte-for-byte otherwise.
pub fn strip_ansi(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != 0x1b {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            break;
        }
        match bytes[i] {
            b'[' => {
                // CSI: ESC [ ... final byte 0x40..=0x7e
                i += 1;
                while i < bytes.len() {
                    let b = bytes[i];
                    i += 1;
                    if (0x40..=0x7e).contains(&b) {
                        break;
                    }
                }
            }
            b']' => {
                // OSC: ESC ] ... BEL or ESC \
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            _ => {
                // Two-byte escape (e.g. ESC ( B, ESC 7).
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_color() {
        assert_eq!(strip_ansi(b"\x1b[31mPassword:\x1b[0m "), "Password: ");
        assert_eq!(strip_ansi(b"plain"), "plain");
    }

    #[test]
    fn strips_osc_title() {
        assert_eq!(strip_ansi(b"\x1b]0;title\x07hello"), "hello");
        assert_eq!(strip_ansi(b"\x1b]0;title\x1b\\hello"), "hello");
    }

    #[test]
    fn matches_default_password_prompts() {
        assert!(prompt_matches("root@host's password: ", None));
        assert!(prompt_matches("Password:", None));
        assert!(prompt_matches("Enter passphrase for key: ", None));
        assert!(!prompt_matches("Welcome to the machine\r\n", None));
    }

    #[test]
    fn matches_custom_prompt() {
        assert!(prompt_matches("Mot de passe: ", Some("Mot de passe")));
        assert!(!prompt_matches("Password: ", Some("Mot de passe")));
    }

    #[test]
    fn detects_host_key_prompts() {
        assert!(is_host_key_prompt(
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        ));
        assert!(is_host_key_prompt("The authenticity of host 'x' can't be established."));
        assert!(!is_host_key_prompt("root@host's password: "));
    }

    #[test]
    fn scanner_sends_once_per_prompt() {
        let mut scanner = PromptScanner::new(None);
        assert!(!scanner.feed(b"Welcome\r\n"));
        assert!(scanner.feed(b"root@host's password: "));
        assert_eq!(scanner.sends(), 1);
        // Immediate duplicate is suppressed by the cooldown.
        assert!(!scanner.feed(b"password: "));
    }

    #[test]
    fn scanner_handles_split_prompt() {
        let mut scanner = PromptScanner::new(None);
        assert!(!scanner.feed(b"root@host's pass"));
        assert!(scanner.feed(b"word: "));
    }

    #[test]
    fn scanner_stops_after_three_sends() {
        let mut scanner = PromptScanner::new(None);
        for _ in 0..5 {
            std::thread::sleep(SEND_COOLDOWN + Duration::from_millis(10));
            scanner.feed(b"Password: ");
        }
        assert_eq!(scanner.sends(), 3);
    }

    #[test]
    fn strips_cursor_query() {
        assert_eq!(strip_cursor_query(b"\x1b[6nhello"), b"hello");
        assert_eq!(strip_cursor_query(b"a\x1b[6nb"), b"ab");
    }

    #[test]
    fn redactor_removes_password() {
        let mut redactor = Redactor::new(b"secret");
        redactor.activate();
        assert_eq!(redactor.filter(b"Password: secret\r\n"), b"Password: \r\n");
    }

    #[test]
    fn redactor_handles_split_password() {
        let mut redactor = Redactor::new(b"secret");
        redactor.activate();
        assert_eq!(redactor.filter(b"Password: sec"), b"Password: ");
        assert_eq!(redactor.filter(b"ret\r\n"), b"\r\n");
    }

    #[test]
    fn redactor_passes_through_other_output() {
        let mut redactor = Redactor::new(b"secret");
        redactor.activate();
        assert_eq!(redactor.filter(b"hello\r\n"), b"hello\r\n");
    }
}
