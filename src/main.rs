use sshpass_win::cli::{self, ParseOutcome};
use sshpass_win::engine;
use sshpass_win::password;
use sshpass_win::which;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    if engine::askpass::is_helper_invocation() {
        engine::askpass::helper();
    }

    match run() {
        Ok(code) => ExitCode::from(normalize_exit_code(code)),
        Err(message) => {
            eprintln!("sshpass: {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let cli = match cli::parse(args)? {
        ParseOutcome::Help => {
            cli::print_help();
            return Ok(0);
        }
        ParseOutcome::Version => {
            cli::print_version();
            return Ok(0);
        }
        ParseOutcome::Run(cli) => cli,
    };

    let secret = Arc::new(password::resolve(&cli.password)?);
    let program = which::resolve(&cli.program)?;

    if let Ok(current) = std::env::current_exe() {
        if current == program.path {
            return Err("refusing to run sshpass recursively".to_string());
        }
    }

    if cli.verbose {
        eprintln!("sshpass: password source: {}", password::describe(&cli.password));
        eprintln!("sshpass: program: {}", program.path.display());
    }

    let engine = engine::choose(&program, cli.verbose)?;
    engine::run(engine, &cli, &program.path, secret, cli.verbose)
}

fn normalize_exit_code(code: i32) -> u8 {
    // Windows exit codes are 32-bit; the process exit status is an 8-bit
    // value in Rust's ExitCode.  Preserve the low byte, which is what shells
    // and DSH report for ordinary command failures.
    (code & 0xff) as u8
}
