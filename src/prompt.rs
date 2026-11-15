//! Password-prompt detection.
//!
//! sshpass looks for `assword` (the built-in `PASSWORD_PROMPT`) or a caller
//! supplied `-P` string. It also watches for the "unknown host key" message.
//!
//! A pty stream contains ANSI escape sequences, carriage returns and screen
//! updates, so matching runs on a short rolling window of printable output.

pub const DEFAULT_PROMPT: &str = "assword";
pub const HOST_KEY_UNKNOWN: &str = "The authenticity of host ";

pub fn prompt_matches(text: &str, custom: &str) -> bool {
    // -P replaces the marker entirely; otherwise sshpass's default is used.
    text.contains(custom)
}

pub fn is_host_key_prompt(text: &str) -> bool {
    text.contains(HOST_KEY_UNKNOWN)
}

/// The interactive wording ssh uses when it asks whether to trust a new host
/// key. askpass helpers can be invoked for this prompt, and a password must
/// never be typed as the answer.
pub fn is_host_key_question(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("yes/no")
        || lower.contains("continue connecting")
        || lower.contains("fingerprint")
        || lower.contains("authenticity")
}

/// Remove ConPTY's own decorations: the window title it sets to the child
/// executable's path, and the input/focus-mode toggles it emits. Legitimate
/// application output (including remote OSC titles and colours) is preserved.
pub fn strip_conpty_noise(bytes: &[u8]) -> Vec<u8> {
    const TOGGLES: [&[u8]; 6] = [
        b"\x1b[?9001h",
        b"\x1b[?9001l",
        b"\x1b[?1004h",
        b"\x1b[?1004l",
        b"\x1b[?25h",
        b"\x1b[?25l",
    ];

    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b']' {
            let start = i;
            let mut end = i + 2;
            let mut terminator = None;
            while end < bytes.len() {
                if bytes[end] == 0x07 {
                    terminator = Some(end + 1);
                    break;
                }
                if bytes[end] == 0x1b && end + 1 < bytes.len() && bytes[end + 1] == b'\\' {
                    terminator = Some(end + 2);
                    break;
                }
                end += 1;
            }
            if let Some(end) = terminator {
                let payload = String::from_utf8_lossy(&bytes[start + 2..end]);
                let lower = payload.to_lowercase();
                let is_conpty_title = payload.starts_with("0;")
                    && (payload.contains(":\\") || lower.contains(".exe"));
                if !is_conpty_title {
                    out.extend_from_slice(&bytes[start..end]);
                }
                i = end;
                continue;
            }
        }
        if let Some(toggle) = TOGGLES.iter().find(|seq| bytes[i..].starts_with(seq)) {
            i += toggle.len();
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Remove ConPTY's cursor-position query (`ESC [ 6 n`) from the output stream.
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

/// Removes the password from the terminal echo that follows typing it.
///
/// OpenSSH disables console echo while reading the password, but an arbitrary
/// console program may echo it. Original sshpass disables ECHO on its pty;
/// ConPTY has no master-side termios, so we redact the exact password until
/// the end of the line that carries the echo, then relay everything normally.
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
        if self.secret.is_empty() {
            self.active = false;
            return;
        }
        self.active = true;
        self.carry.clear();
    }

    pub fn filter(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.active {
            return chunk.to_vec();
        }
        self.carry.extend_from_slice(chunk);

        // The echo is a single line. Redact only up to its newline; everything
        // after that is ordinary program output and must pass through intact
        // (even if it happens to contain the password text).
        if let Some(newline) = self.carry.iter().position(|byte| *byte == b'\n') {
            let mut out = remove_all(&self.carry[..=newline], &self.secret);
            out.extend_from_slice(&self.carry[newline + 1..]);
            self.active = false;
            self.carry.clear();
            return out;
        }

        // Hold a trailing partial password for the next chunk.
        let mut keep = 0usize;
        for candidate in (1..self.secret.len().min(self.carry.len()) + 1).rev() {
            if self.carry[self.carry.len() - candidate..] == self.secret[..candidate] {
                keep = candidate;
                break;
            }
        }
        let process_len = self.carry.len() - keep;
        let out = remove_all(&self.carry[..process_len], &self.secret);
        self.carry = self.carry[process_len..].to_vec();
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        let out = std::mem::take(&mut self.carry);
        self.active = false;
        out
    }
}

fn remove_all(haystack: &[u8], needle: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0usize;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Remove ANSI CSI/OSC sequences so prompt matching is not confused by color
/// or cursor-control codes. UTF-8 text is preserved byte-for-byte otherwise.
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
            _ => i += 1,
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
    fn matches_default_prompts() {
        assert!(prompt_matches("root@host's password: ", DEFAULT_PROMPT));
        assert!(prompt_matches("Password:", DEFAULT_PROMPT));
        assert!(!prompt_matches("Welcome\r\n", DEFAULT_PROMPT));
    }

    #[test]
    fn custom_prompt_replaces_default() {
        assert!(prompt_matches("Mot de passe: ", "Mot de passe"));
        assert!(!prompt_matches("Password: ", "Mot de passe"));
    }

    #[test]
    fn detects_host_key_message() {
        assert!(is_host_key_prompt(
            "The authenticity of host 'x' can't be established."
        ));
        assert!(!is_host_key_prompt("root@host's password: "));
    }

    #[test]
    fn strips_cursor_query() {
        assert_eq!(strip_cursor_query(b"\x1b[6nhello"), b"hello");
        assert_eq!(strip_cursor_query(b"a\x1b[6nb"), b"ab");
    }

    #[test]
    fn strips_conpty_decorations_only() {
        assert_eq!(
            strip_conpty_noise(b"\x1b]0;C:\\Windows\\ssh.exe\x07hello"),
            b"hello"
        );
        assert_eq!(strip_conpty_noise(b"\x1b[?9001hhello\x1b[?9001l"), b"hello");
        // A remote title (no Windows path / .exe) is legitimate output.
        assert_eq!(
            strip_conpty_noise(b"\x1b]0;my-server\x07hello"),
            b"\x1b]0;my-server\x07hello"
        );
    }

    #[test]
    fn redactor_removes_only_the_echo_line() {
        let mut redactor = Redactor::new(b"K");
        redactor.activate();
        assert_eq!(redactor.filter(b"K\r\nAUTH_OK\r\n"), b"\r\nAUTH_OK\r\n");
        // Once the echo line is gone, redaction is off.
        assert_eq!(redactor.filter(b"AUTH_OK\r\n"), b"AUTH_OK\r\n");
    }

    #[test]
    fn redactor_handles_split_password() {
        let mut redactor = Redactor::new(b"secret");
        redactor.activate();
        assert_eq!(redactor.filter(b"sec"), b"");
        assert_eq!(redactor.filter(b"ret\r\nOK"), b"\r\nOK");
    }

    #[test]
    fn redactor_passes_other_output() {
        let mut redactor = Redactor::new(b"secret");
        redactor.activate();
        assert_eq!(redactor.filter(b"hello\r\n"), b"hello\r\n");
    }
}
