//! Live tests against a real OpenSSH server.
//!
//! Skipped unless the environment provides:
//!   SSHPASS_TEST_HOST, SSHPASS_TEST_USER, SSHPASS_TEST_PASSWORD
//!
//! Run with:
//!   cargo test --features test-helpers --test ssh_integration -- --test-threads=1

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

const SSHPASS: &str = env!("CARGO_BIN_EXE_sshpass");
static LOCK: Mutex<()> = Mutex::new(());

struct Target {
    host: String,
    user: String,
    password: String,
}

fn target() -> Option<Target> {
    let host = std::env::var("SSHPASS_TEST_HOST").ok()?;
    let user = std::env::var("SSHPASS_TEST_USER").ok()?;
    let password = std::env::var("SSHPASS_TEST_PASSWORD").ok()?;
    Some(Target {
        host,
        user,
        password,
    })
}

fn destination(target: &Target) -> String {
    format!("{}@{}", target.user, target.host)
}

fn base() -> Command {
    let mut cmd = Command::new(SSHPASS);
    for key in [
        "SSHPASS_RS_ENGINE",
        "SSHPASS_RS_ASKPASS",
        "SSHPASS_RS_PASSWORD",
        "SSHPASS_RS_PROMPT",
        "SSHPASS_RS_PROMPT_COUNT",
        "SSHPASS",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

fn run(mut cmd: Command, stdin: Option<&[u8]>) -> Output {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn sshpass");
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data).unwrap();
    }
    child.wait_with_output().expect("wait")
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn temp_known_hosts(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sshpass-win-{}-{}-{}",
        std::process::id(),
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn ssh_options() -> Vec<String> {
    vec![
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=3".into(),
    ]
}

#[test]
fn askpass_echo() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("echo ASKPASS_OK; id -un");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    let body = out(&output);
    assert!(body.contains("ASKPASS_OK"), "{body}");
    assert!(body.contains(&target.user), "{body}");
}

#[test]
fn askpass_exit_code() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("exit 7");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(7), "{}", err(&output));
}

#[test]
fn askpass_stdin_payload() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("cat");
    let input = format!("{}\npayload-from-stdin\n", target.password);
    let output = run(cmd, Some(input.as_bytes()));
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(
        out(&output).contains("payload-from-stdin"),
        "{}",
        out(&output)
    );
}

#[test]
fn password_sources_against_ssh() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();

    let mut env_cmd = base();
    env_cmd.env("SSHPASS", &target.password);
    env_cmd.args(["-e", "ssh"]);
    env_cmd.args(ssh_options());
    env_cmd.arg(destination(&target));
    env_cmd.arg("echo ENV_OK");
    let output = run(env_cmd, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("ENV_OK"));

    let path = std::env::temp_dir().join(format!("sshpass-win-live-{}.txt", std::process::id()));
    std::fs::write(&path, format!("{}\n", target.password)).unwrap();
    let mut file_cmd = base();
    file_cmd.arg("-f").arg(&path).arg("ssh");
    file_cmd.args(ssh_options());
    file_cmd.arg(destination(&target));
    file_cmd.arg("echo FILE_OK");
    let output = run(file_cmd, None);
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("FILE_OK"));

    let mut fd_cmd = base();
    fd_cmd.args(["-d", "0", "ssh"]);
    fd_cmd.args(ssh_options());
    fd_cmd.arg(destination(&target));
    fd_cmd.arg("echo FD_OK");
    let input = format!("{}\n", target.password);
    let output = run(fd_cmd, Some(input.as_bytes()));
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("FD_OK"));

    let mut stdin_cmd = base();
    stdin_cmd.arg("ssh");
    stdin_cmd.args(ssh_options());
    stdin_cmd.arg(destination(&target));
    stdin_cmd.arg("echo STDIN_OK");
    let output = run(stdin_cmd, Some(input.as_bytes()));
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("STDIN_OK"));
}

#[test]
fn wrong_password_one_prompt_returns_255() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let started = std::time::Instant::now();
    let mut cmd = base();
    cmd.args(["-p", "definitely-wrong-password", "ssh"]);
    cmd.args([
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "NumberOfPasswordPrompts=1",
    ]);
    cmd.arg(destination(&target));
    cmd.arg("true");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(255), "{}", err(&output));
    assert!(err(&output).to_lowercase().contains("permission denied"));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn wrong_password_repeated_prompt_returns_5() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", "definitely-wrong-password", "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("true");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(5), "{}", err(&output));
}

#[test]
fn forced_pty_engine_works_with_ssh() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.env("SSHPASS_RS_ENGINE", "pty");
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("echo PTY_OK");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("PTY_OK"), "{}", out(&output));
}

#[test]
fn forced_pty_wrong_password_returns_5() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.env("SSHPASS_RS_ENGINE", "pty");
    cmd.args(["-p", "definitely-wrong-password", "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("true");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(5), "{}", err(&output));
}

#[test]
fn pty_host_key_unknown_returns_6() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let known_hosts = temp_known_hosts("unknown");
    let mut cmd = base();
    cmd.env("SSHPASS_RS_ENGINE", "pty");
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    cmd.args(["-o", "StrictHostKeyChecking=ask"]);
    cmd.arg(destination(&target));
    cmd.arg("true");
    let output = run(cmd, None);
    let _ = std::fs::remove_file(&known_hosts);
    assert_eq!(output.status.code(), Some(6), "{}", err(&output));
}

#[test]
fn tty_flag_uses_the_pty_engine() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let known_hosts = temp_known_hosts("tty");
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh", "-tt"]);
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    cmd.args(["-o", "StrictHostKeyChecking=accept-new"]);
    cmd.arg(destination(&target));
    cmd.arg("echo TTY_OK");
    let output = run(cmd, None);
    let _ = std::fs::remove_file(&known_hosts);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("TTY_OK"), "{}", out(&output));
}

#[test]
fn utf8_output() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("printf '\\344\\270\\255\\346\\226\\207-OK\\n'");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("中文-OK"), "{}", out(&output));
}

#[test]
fn large_remote_output() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let mut cmd = base();
    cmd.args(["-p", &target.password, "ssh"]);
    cmd.args(ssh_options());
    cmd.arg(destination(&target));
    cmd.arg("i=1; while [ $i -le 200 ]; do echo LINE$i; i=$((i+1)); done");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    let body = out(&output);
    assert!(
        body.contains("LINE1\r\n") || body.contains("LINE1\n"),
        "{body}"
    );
    assert!(body.contains("LINE200"), "{body}");
}

#[test]
fn scp_legacy_protocol() {
    let Some(target) = target() else { return };
    let _guard = LOCK.lock().unwrap();
    let local = std::env::temp_dir().join(format!("sshpass-win-scp-{}.txt", std::process::id()));
    std::fs::write(&local, b"scp-payload-123").unwrap();
    let remote = format!("/tmp/sshpass-win-scp-{}.txt", std::process::id());

    let mut upload = base();
    upload.args(["-p", &target.password, "scp", "-O"]);
    upload.args(ssh_options());
    upload.arg(&local);
    upload.arg(format!("{}:{}", destination(&target), remote));
    let output = run(upload, None);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));

    let mut verify = base();
    verify.args(["-p", &target.password, "ssh"]);
    verify.args(ssh_options());
    verify.arg(destination(&target));
    verify.arg(format!("cat {remote}; rm -f {remote}"));
    let output = run(verify, None);
    let _ = std::fs::remove_file(&local);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert!(out(&output).contains("scp-payload-123"), "{}", out(&output));
}
