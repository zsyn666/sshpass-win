use sshpass_win::cli::{self, Outcome, ParseError};
use sshpass_win::engine;
use sshpass_win::exit;
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
        Err(code) => ExitCode::from(code.clamp(0, 255) as u8),
    }
}

fn run() -> Result<i32, i32> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let cli = match cli::parse(args) {
        Ok(Outcome::Help) => {
            cli::print_usage();
            return Ok(exit::NOERROR);
        }
        Ok(Outcome::Version) => {
            cli::print_version();
            return Ok(exit::NOERROR);
        }
        Ok(Outcome::NoCommand) => {
            cli::print_usage();
            return Ok(exit::NOERROR);
        }
        Ok(Outcome::Run(cli)) => cli,
        Err(ParseError(code)) => {
            eprintln!("Use \"sshpass -h\" to get help");
            return Err(code);
        }
    };

    let secret = match password::resolve(&cli.password) {
        Ok(secret) => Arc::new(secret),
        Err(message) => {
            eprintln!("{message}");
            return Err(exit::RUNTIME_ERROR);
        }
    };

    let program = match which::resolve(&cli.program) {
        Ok(program) => program,
        Err(message) => {
            eprintln!("SSHPASS: Failed to run command: {message}");
            return Err(exit::RUNTIME_ERROR);
        }
    };

    if let Ok(current) = std::env::current_exe() {
        if current == program.path {
            eprintln!("SSHPASS: refusing to run sshpass recursively");
            return Err(exit::RUNTIME_ERROR);
        }
    }

    let engine = match engine::choose(&cli, &program) {
        Ok(engine) => engine,
        Err(message) => {
            eprintln!("{message}");
            return Err(exit::INVALID_ARGUMENTS);
        }
    };

    match engine::run(engine, &cli, &program.path, secret, cli.verbose > 0) {
        Ok(code) => Ok(code),
        Err(message) => {
            eprintln!("{message}");
            Err(exit::RUNTIME_ERROR)
        }
    }
}

fn normalize_exit_code(code: i32) -> u8 {
    // Windows exit codes are 32-bit; Rust's ExitCode is 8-bit. ssh only uses
    // 0-255, so clamp anything else instead of silently wrapping 256 to 0.
    if code < 0 {
        255
    } else {
        code.min(255) as u8
    }
}
