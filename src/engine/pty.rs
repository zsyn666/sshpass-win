//! ConPTY engine.
//!
//! This is the Windows equivalent of sshpass's pty loop: spawn any console
//! program inside a pseudo console, relay output, watch for a password prompt
//! and type the password.  It is used for non-OpenSSH programs and can be
//! forced for OpenSSH with `SSHPASS_RS_ENGINE=pty`.
//!
//! OpenSSH itself normally uses the askpass engine, which does not need a pty
//! and is more robust.  This engine exists so that sshpass's "run any command"
//! contract is honoured.

use crate::cli::{Cli, PasswordSource};
use crate::prompt::{strip_cursor_query, PromptScanner, Redactor};
use crate::secret::Secret;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type SharedWriter = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

pub fn run(
    cli: &Cli,
    program: &Path,
    password: Arc<Secret>,
    verbose: bool,
) -> Result<i32, String> {
    if verbose {
        eprintln!("sshpass: engine: pty (ConPTY)");
        eprintln!("sshpass: program: {}", program.display());
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 30,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|err| format!("cannot allocate a pseudo console: {err:#}"))?;

    let mut builder = CommandBuilder::new(program);
    builder.args(&cli.args);
    let mut child = pair
        .slave
        .spawn_command(builder)
        .map_err(|err| format!("cannot start {}: {err:#}", program.display()))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|err| format!("cannot read from the pseudo console: {err:#}"))?;
    let writer: SharedWriter = Arc::new(Mutex::new(Some(
        pair.master
            .take_writer()
            .map_err(|err| format!("cannot write to the pseudo console: {err:#}"))?,
    )));

    let (done_tx, done_rx) = mpsc::channel::<()>();

    // Output relay + prompt detection.
    let reader_writer = Arc::clone(&writer);
    let reader_password = Arc::clone(&password);
    let prompt = cli.prompt.clone();
    let verbose_reader = verbose;
    thread::spawn(move || {
        let mut scanner = PromptScanner::new(prompt);
        let mut redactor = Redactor::new(reader_password.expose().as_bytes());
        let mut stdout = std::io::stdout();
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let tail = redactor.flush();
                    if !tail.is_empty() {
                        let _ = stdout.write_all(&tail);
                        let _ = stdout.flush();
                    }
                    break;
                }
                Ok(count) => {
                    let cleaned = strip_cursor_query(&buffer[..count]);
                    let visible = redactor.filter(&cleaned);
                    if !visible.is_empty() {
                        let _ = stdout.write_all(&visible);
                        let _ = stdout.flush();
                    }

                    // portable-pty creates the pseudo console with
                    // PSEUDOCONSOLE_INHERIT_CURSOR, which makes ConPTY emit a
                    // "device status report" query (ESC [ 6 n) and wait for the
                    // host terminal to answer with a cursor position.  There is
                    // no real terminal here, so answer it ourselves.
                    if buffer[..count]
                        .windows(4)
                        .any(|window| window == b"\x1b[6n")
                    {
                        if let Ok(mut guard) = reader_writer.lock() {
                            if let Some(writer) = guard.as_mut() {
                                let _ = writer.write_all(b"\x1b[1;1R");
                                let _ = writer.flush();
                            }
                        }
                    }

                    if scanner.feed(&buffer[..count]) {
                        if verbose_reader {
                            eprintln!("sshpass: detected password prompt; sending password");
                        }
                        if let Ok(mut guard) = reader_writer.lock() {
                            if let Some(writer) = guard.as_mut() {
                                let _ = writer.write_all(reader_password.expose().as_bytes());
                                let _ = writer.write_all(b"\r");
                                let _ = writer.flush();
                                redactor.activate();
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = done_tx.send(());
    });

    // Relay stdin unless it was consumed to obtain the password.
    if !matches!(cli.password, PasswordSource::Stdin | PasswordSource::Fd(0)) {
        let input_writer = Arc::clone(&writer);
        thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buffer = [0u8; 4096];
            let mut previous: Option<u8> = None;
            loop {
                match stdin.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        // A console child in line-input mode only submits a line
                        // on CR, so turn a bare LF into CRLF the way a terminal
                        // would when the user presses Enter.
                        let mut payload = Vec::with_capacity(count + 8);
                        for &byte in &buffer[..count] {
                            if byte == b'\n' && previous != Some(b'\r') {
                                payload.push(b'\r');
                            }
                            payload.push(byte);
                            previous = Some(byte);
                        }
                        if let Ok(mut guard) = input_writer.lock() {
                            if let Some(writer) = guard.as_mut() {
                                if writer.write_all(&payload).is_err() {
                                    break;
                                }
                                let _ = writer.flush();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Ctrl+C in our console does not reach a ConPTY child automatically.
    // Translate it into the terminal's ETX byte.
    let signal_writer = Arc::clone(&writer);
    let _ = ctrlc::set_handler(move || {
        if let Ok(mut guard) = signal_writer.lock() {
            if let Some(writer) = guard.as_mut() {
                let _ = writer.write_all(b"\x03");
                let _ = writer.flush();
            }
        }
    });

    let status = child
        .wait()
        .map_err(|err| format!("error while waiting for the child: {err}"))?;

    // Close the write side so the reader can observe EOF, then give the
    // reader a moment to flush anything still buffered.
    if let Ok(mut guard) = writer.lock() {
        *guard = None;
    }
    let _ = done_rx.recv_timeout(Duration::from_millis(750));
    drop(pair.master);

    let code = status.exit_code() as i32;
    if verbose {
        match status.signal() {
            Some(signal) => eprintln!("sshpass: child terminated by {signal}; reporting {code}"),
            None => eprintln!("sshpass: child exited with status {code}"),
        }
    }
    Ok(code)
}
