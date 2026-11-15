use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const SSHPASS: &str = env!("CARGO_BIN_EXE_sshpass");
const FAKE_PROMPT: &str = env!("CARGO_BIN_EXE_fake-prompt");
const FAKE_INPUT: &str = env!("CARGO_BIN_EXE_fake-input");

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn base() -> Command {
    let mut cmd = Command::new(SSHPASS);
    for key in [
        "SSHPASS_RS_ENGINE",
        "SSHPASS_RS_ASKPASS",
        "SSHPASS_RS_PASSWORD",
        "SSHPASS_RS_PROMPT",
        "SSHPASS_RS_PROMPT_COUNT",
        "SSHPASS",
        "FAKE_PROMPT_PASSWORD",
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
    let mut child = cmd.spawn().expect("failed to spawn sshpass");
    if let Some(data) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(data)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait for sshpass")
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn temp_path(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "sshpass-win-{}-{}-{}-{}",
        std::process::id(),
        n,
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn help_and_version_match_sshpass_shape() {
    let help = run(
        {
            let mut cmd = base();
            cmd.arg("-h");
            cmd
        },
        None,
    );
    assert!(help.status.success());
    let body = text(&help);
    assert!(body.contains("Usage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters"));
    assert!(body.contains("-e[env_var]"));
    assert!(body.contains("At most one of -f, -d, -p or -e should be used."));

    let version = run(
        {
            let mut cmd = base();
            cmd.arg("-V");
            cmd
        },
        None,
    );
    assert!(version.status.success());
    let body = text(&version);
    assert!(body.contains("sshpass 1.0.0"), "{body}");
    assert!(body.contains("Using \"assword\" as the default password prompt indicator."));
}

#[test]
fn no_command_prints_help_and_succeeds() {
    for args in [vec![], vec!["-p", "x"], vec!["-v"]] {
        let output = run(
            {
                let mut cmd = base();
                cmd.args(&args);
                cmd
            },
            None,
        );
        assert_eq!(output.status.code(), Some(0), "args={args:?}");
        assert!(text(&output).contains("Usage: sshpass"), "args={args:?}");
    }
}

#[test]
fn usage_errors_match_sshpass() {
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["-q", "ssh"], "invalid option"),
        (vec!["-d"], "requires an argument"),
        (vec!["-p"], "requires an argument"),
        (vec!["-f"], "requires an argument"),
        (vec!["-P"], "requires an argument"),
        (vec!["--help"], "invalid option"),
    ];
    for (args, needle) in cases {
        let output = run(
            {
                let mut cmd = base();
                cmd.args(&args);
                cmd
            },
            None,
        );
        assert_eq!(output.status.code(), Some(1), "args={args:?}");
        assert!(
            err_text(&output).contains(needle),
            "args={args:?} stderr={}",
            err_text(&output)
        );
        assert!(err_text(&output).contains("Use \"sshpass -h\" to get help"));
    }
}

#[test]
fn conflicting_password_sources_exit_two() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS", "x");
            cmd.args(["-p", "a", "-e", "ssh"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(2), "{}", err_text(&output));
    assert!(err_text(&output).contains("Conflicting password source"));

    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "a", "-p", "b", "ssh"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(err_text(&output).contains("Conflicting password source"));
}

#[test]
fn missing_environment_variable_exits_one() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-e", "ssh"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        err_text(&output)
            .contains("-e option given but \"SSHPASS\" environment variable is not set."),
        "{}",
        err_text(&output)
    );
}

#[test]
fn custom_environment_variable_name() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("MY_SSH_PW", "secret");
            cmd.args(["-eMY_SSH_PW", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"));

    // With a space, the extra token is the command, not an env-var name.
    let output = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS", "secret");
            cmd.env("MY_SSH_PW", "secret");
            cmd.args(["-e", "MY_SSH_PW"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(3), "{}", err_text(&output));
    assert!(err_text(&output).contains("Failed to run command"));
}

#[test]
fn password_argument_and_redaction() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "secret", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"), "{}", text(&output));
    assert!(
        !text(&output).contains("secret"),
        "password leaked: {}",
        text(&output)
    );
}

#[test]
fn short_password_does_not_eat_later_output() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("FAKE_PROMPT_PASSWORD", "K");
            cmd.args(["-p", "K", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(
        text(&output).contains("AUTH_OK"),
        "redactor ate normal output: {}",
        text(&output)
    );
}

#[test]
fn wrong_password_propagates_child_exit_code() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "wrong-value", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(7), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_FAIL"), "{}", text(&output));
}

#[test]
fn password_from_file() {
    let path = temp_path("pw.txt");
    std::fs::write(&path, b"secret\r\nignored\n").unwrap();
    let output = run(
        {
            let mut cmd = base();
            cmd.arg("-f").arg(&path).args(["--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"));
}

#[test]
fn password_from_stdin_and_fd_zero() {
    for args in [vec!["-d", "0", "--", FAKE_PROMPT], vec!["--", FAKE_PROMPT]] {
        let output = run(
            {
                let mut cmd = base();
                cmd.args(&args);
                cmd
            },
            Some(b"secret\n"),
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "args={args:?} {}",
            err_text(&output)
        );
        assert!(text(&output).contains("AUTH_OK"), "{}", text(&output));
    }
}

#[test]
fn fd_parsing_uses_atoi() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-d", "abc", "--", FAKE_PROMPT]);
            cmd
        },
        Some(b"secret\n"),
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"));
}

#[test]
fn custom_prompt_option() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "secret", "-P", "Password", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"));
}

#[test]
fn verbose_uses_sshpass_prefix_and_no_password() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-v", "-p", "secret", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    let diagnostics = err_text(&output);
    assert!(
        diagnostics.contains("SSHPASS: searching for password prompt using match \"assword\""),
        "{diagnostics}"
    );
    assert!(
        diagnostics.contains("SSHPASS: detected prompt. Sending password."),
        "{diagnostics}"
    );
    assert!(!diagnostics.contains("secret"), "{diagnostics}");
}

#[test]
fn stdin_is_forwarded_to_the_pty_child() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "secret", "--", FAKE_INPUT]);
            cmd
        },
        Some(b"hello-from-test\n"),
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(
        text(&output).contains("GOT:hello-from-test"),
        "{}",
        text(&output)
    );
}

#[test]
fn exit_code_from_console_program() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "x", "--", "cmd.exe", "/c", "exit 3"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(3), "{}", err_text(&output));
}

#[test]
fn large_output_is_relayed() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args([
                "-p",
                "x",
                "--",
                "cmd.exe",
                "/c",
                "for /L %i in (1,1,120) do @echo LINE%i",
            ]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    let body = text(&output);
    for i in [1, 2, 60, 120] {
        assert!(
            body.contains(&format!("LINE{i}")),
            "missing LINE{i}: {body}"
        );
    }
}

#[test]
fn sftp_is_routed_to_the_pty_engine() {
    let dir = temp_path("fakebin");
    std::fs::create_dir_all(&dir).unwrap();
    let fake_sftp = dir.join("sftp.exe");
    std::fs::copy(FAKE_PROMPT, &fake_sftp).unwrap();

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![dir.clone()];
    paths.extend(std::env::split_paths(&old_path));
    let new_path = std::env::join_paths(paths).unwrap();

    let output = run(
        {
            let mut cmd = base();
            cmd.env("PATH", &new_path);
            cmd.args(["-p", "secret", "sftp"]);
            cmd
        },
        None,
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_OK"), "{}", text(&output));
}

#[test]
fn askpass_helper_prints_password() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS_RS_ASKPASS", "1");
            cmd.env("SSHPASS_RS_PASSWORD", "secret");
            cmd.arg("root@host's password: ");
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(text(&output), "secret\n");
}

#[test]
fn askpass_helper_refuses_host_key_question() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS_RS_ASKPASS", "1");
            cmd.env("SSHPASS_RS_PASSWORD", "secret");
            cmd.arg("Are you sure you want to continue connecting (yes/no/[fingerprint])? ");
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        err_text(&output).contains("host-key"),
        "{}",
        err_text(&output)
    );
    assert!(!text(&output).contains("secret"));
}

#[test]
fn askpass_helper_honours_custom_prompt() {
    let ok = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS_RS_ASKPASS", "1");
            cmd.env("SSHPASS_RS_PASSWORD", "secret");
            cmd.env("SSHPASS_RS_PROMPT", "Password");
            cmd.arg("Password: ");
            cmd
        },
        None,
    );
    assert_eq!(ok.status.code(), Some(0));
    assert_eq!(text(&ok), "secret\n");

    let bad = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS_RS_ASKPASS", "1");
            cmd.env("SSHPASS_RS_PASSWORD", "secret");
            cmd.env("SSHPASS_RS_PROMPT", "Password");
            cmd.arg("Verification code: ");
            cmd
        },
        None,
    );
    assert_eq!(bad.status.code(), Some(1));
    assert!(!text(&bad).contains("secret"));
}

#[test]
fn askpass_helper_without_password_fails() {
    let output = run(
        {
            let mut cmd = base();
            cmd.env("SSHPASS_RS_ASKPASS", "1");
            cmd.arg("Password: ");
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(err_text(&output).contains("without a password"));
}

#[test]
fn missing_program_exits_three() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "x", "definitely-not-a-real-program-xyz"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(err_text(&output).contains("Failed to run command"));
}

#[test]
fn non_stdin_fd_behaves_like_an_unreadable_descriptor() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-d", "9", "--", FAKE_PROMPT]);
            cmd
        },
        None,
    );
    // sshpass reads nothing from an unusable descriptor and sends an empty
    // password, so the child rejects it.
    assert_eq!(output.status.code(), Some(7), "{}", err_text(&output));
    assert!(text(&output).contains("AUTH_FAIL"), "{}", text(&output));
}

#[test]
fn double_dash_hands_dash_arguments_to_the_program() {
    let output = run(
        {
            let mut cmd = base();
            cmd.args(["-p", "x", "--", "-definitely-missing"]);
            cmd
        },
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(err_text(&output).contains("Failed to run command"));
}
