//! ConPTY engine.
//!
//! This is the Windows equivalent of sshpass's pty loop: give the child a
//! console, relay its output, watch for a password prompt and type the
//! password. It is used for `sftp`, any non-OpenSSH command, and whenever
//! `SSHPASS_RS_ENGINE=pty` is set.
//!
//! It also reproduces sshpass's error policy: a second password prompt means
//! the password was wrong (exit 5), and "The authenticity of host" means the
//! host key is unknown (exit 6).

use crate::cli::{Cli, PasswordSource};
use crate::prompt::{
    is_host_key_prompt, strip_ansi, strip_conpty_noise, strip_cursor_query, Redactor,
};
use crate::secret::Secret;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type SharedWriter = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

#[derive(Debug, Clone, Copy)]
enum Event {
    FirstPrompt,
    SecondPrompt,
    HostKeyUnknown,
    Done,
}

pub fn run(cli: &Cli, program: &Path, password: Arc<Secret>, verbose: bool) -> Result<i32, String> {
    if verbose {
        eprintln!(
            "SSHPASS: searching for password prompt using match \"{}\"",
            cli.prompt
        );
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 30,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|err| format!("SSHPASS: Failed to get a pseudo terminal: {err:#}"))?;

    let mut builder = CommandBuilder::new(program);
    builder.args(&cli.args);
    let mut child = pair
        .slave
        .spawn_command(builder)
        .map_err(|err| format!("SSHPASS: Failed to run command: {err:#}"))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|err| format!("SSHPASS: Failed to read pseudo terminal: {err:#}"))?;
    let writer: SharedWriter =
        Arc::new(Mutex::new(Some(pair.master.take_writer().map_err(
            |err| format!("SSHPASS: Failed to write pseudo terminal: {err:#}"),
        )?)));

    let (event_tx, event_rx) = mpsc::channel::<Event>();

    // Output relay, prompt detection and password injection.
    let reader_writer = Arc::clone(&writer);
    let reader_password = Arc::clone(&password);
    let prompt = cli.prompt.clone();
    let verbose_reader = verbose;
    thread::spawn(move || {
        let mut redactor = Redactor::new(reader_password.expose().as_bytes());
        let mut tail = String::new();
        let mut sent = false;
        let mut stdout = std::io::stdout();
        let mut buffer = [0u8; 8192];
        let mut output_started = false;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let tail_bytes = redactor.flush();
                    if !tail_bytes.is_empty() {
                        let _ = stdout.write_all(&tail_bytes);
                        let _ = stdout.flush();
                    }
                    let _ = event_tx.send(Event::Done);
                    break;
                }
                Ok(count) => {
                    let raw = &buffer[..count];
                    let mut cleaned = strip_conpty_noise(raw);
                    // ConPTY starts the stream with an SGR reset.
                    if !output_started && cleaned.starts_with(b"\x1b[m") {
                        cleaned.drain(..3);
                    }

                    let visible = redactor.filter(&strip_cursor_query(&cleaned));
                    if verbose_reader && !visible.is_empty() {
                        eprintln!("SSHPASS: read: {}", String::from_utf8_lossy(&visible));
                    }
                    if !visible.is_empty() {
                        let _ = stdout.write_all(&visible);
                        let _ = stdout.flush();
                        output_started = true;
                    }

                    // portable-pty creates the pseudo console with
                    // PSEUDOCONSOLE_INHERIT_CURSOR, so ConPTY emits a device
                    // status report (ESC [ 6 n) and waits for a cursor
                    // position. There is no real terminal here; answer it.
                    if raw.windows(4).any(|window| window == b"\x1b[6n") {
                        if let Ok(mut guard) = reader_writer.lock() {
                            if let Some(writer) = guard.as_mut() {
                                let _ = writer.write_all(b"\x1b[1;1R");
                                let _ = writer.flush();
                            }
                        }
                    }

                    tail.push_str(&strip_ansi(&cleaned));
                    if tail.len() > 4096 {
                        let mut cut = tail.len() - 4096;
                        while cut < tail.len() && !tail.is_char_boundary(cut) {
                            cut += 1;
                        }
                        tail.drain(..cut);
                    }

                    if is_host_key_prompt(&tail) {
                        let _ = event_tx.send(Event::HostKeyUnknown);
                        break;
                    }

                    if tail.contains(&prompt) {
                        if !sent {
                            sent = true;
                            tail.clear();
                            if verbose_reader {
                                eprintln!("SSHPASS: detected prompt. Sending password.");
                            }
                            let _ = event_tx.send(Event::FirstPrompt);
                            if let Ok(mut guard) = reader_writer.lock() {
                                if let Some(writer) = guard.as_mut() {
                                    let _ = writer.write_all(reader_password.expose().as_bytes());
                                    let _ = writer.write_all(b"\r");
                                    let _ = writer.flush();
                                    redactor.activate();
                                }
                            }
                        } else {
                            if verbose_reader {
                                eprintln!(
                                    "SSHPASS: detected prompt, again. Wrong password. Terminating."
                                );
                            }
                            let _ = event_tx.send(Event::SecondPrompt);
                            break;
                        }
                    }
                }
                Err(_) => {
                    let _ = event_tx.send(Event::Done);
                    break;
                }
            }
        }
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
                        // A console child submits a line only on CR, so turn a
                        // bare LF into CRLF the way a terminal would.
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
    let signal_writer = Arc::clone(&writer);
    let _ = ctrlc::set_handler(move || {
        if let Ok(mut guard) = signal_writer.lock() {
            if let Some(writer) = guard.as_mut() {
                let _ = writer.write_all(b"\x03");
                let _ = writer.flush();
            }
        }
    });

    let exit = loop {
        match event_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Event::SecondPrompt) => {
                let _ = child.kill();
                let _ = child.wait();
                break Some(crate::exit::INCORRECT_PASSWORD);
            }
            Ok(Event::HostKeyUnknown) => {
                let _ = child.kill();
                let _ = child.wait();
                break Some(crate::exit::HOST_KEY_UNKNOWN);
            }
            Ok(Event::FirstPrompt) | Ok(Event::Done) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }

        match child.try_wait() {
            Ok(Some(status)) => break Some(status.exit_code() as i32),
            Ok(None) => {}
            Err(err) => return Err(format!("SSHPASS: error while waiting for the child: {err}")),
        }
    };

    // Close the write side so the reader can observe EOF, then give the reader
    // a moment to flush what is still buffered.
    if let Ok(mut guard) = writer.lock() {
        *guard = None;
    }
    let _ = event_rx.recv_timeout(Duration::from_millis(750));
    drop(pair.master);

    Ok(exit.unwrap_or(crate::exit::RUNTIME_ERROR))
}
