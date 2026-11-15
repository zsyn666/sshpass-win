//! sshpass-compatible command line parsing.
//!
//! The original sshpass accepts:
//!
//! ```text
//! sshpass [-f|-d|-p|-e] [-hV] command parameters
//! ```
//!
//! This module deliberately mirrors that surface, including attached option
//! values (`-psecret`, `-fpass.txt`) and the `--` terminator.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// `-p password`
    Arg(String),
    /// `-e` (read `SSHPASS`)
    Env,
    /// `-f filename`
    File(PathBuf),
    /// `-d number`
    Fd(u32),
    /// No password option: first line of stdin.
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub password: PasswordSource,
    pub prompt: Option<String>,
    pub verbose: bool,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Run(Cli),
    Help,
    Version,
}

pub const USAGE: &str = "\
Usage: sshpass [-f|-d|-p|-e] [-hV] command parameters
  -f filename   Take password to use from file
  -d number     Use number as file descriptor for getting password (Windows: 0 only)
  -p password   Provide password as argument (security unwise)
  -e            Password is passed as env-var \"SSHPASS\"
  -P prompt     Which string should sshpass search for to detect a password prompt
  -v            Be verbose about what you're doing
  -h, --help    Show this help
  -V, --version Show version
With no password option, the first line of stdin is used.
Supported commands: ssh, scp, sftp and arbitrary console programs.";

pub const VERSION: &str = "sshpass 1.0.0 (rust/windows-native)";

/// Parse a full argv (without argv[0]).
pub fn parse<I>(args: I) -> Result<ParseOutcome, String>
where
    I: IntoIterator<Item = OsString>,
{
    let argv: Vec<OsString> = args.into_iter().collect();
    if argv.is_empty() {
        return Err("missing command".to_string());
    }

    let mut password: Option<PasswordSource> = None;
    let mut prompt: Option<String> = None;
    let mut verbose = false;
    let mut index = 0usize;

    while index < argv.len() {
        let arg = &argv[index];
        if arg == OsStr::new("--") {
            index += 1;
            break;
        }

        let Some(text) = arg.to_str() else {
            // A non-UTF-8 first token cannot be an option; treat it as the
            // program.  Everything after it is forwarded verbatim.
            break;
        };

        if !text.starts_with('-') || text == "-" {
            // First non-option: this is the program.
            break;
        }

        // Long options are convenience aliases; sshpass itself only has short
        // options, but accepting them costs nothing.
        if text == "--help" {
            return Ok(ParseOutcome::Help);
        }
        if text == "--version" {
            return Ok(ParseOutcome::Version);
        }

        let mut chars = text[1..].char_indices().peekable();
        while let Some((offset, ch)) = chars.next() {
            match ch {
                'v' => verbose = true,
                'h' => return Ok(ParseOutcome::Help),
                'V' => return Ok(ParseOutcome::Version),
                'e' => password = Some(PasswordSource::Env),
                'p' | 'f' | 'd' | 'P' => {
                    // The value is either the rest of this token or the next
                    // argv element.
                    let rest_start = 1 + offset + ch.len_utf8();
                    let rest = &text[rest_start..];
                    let value: OsString = if !rest.is_empty() {
                        OsString::from(rest)
                    } else {
                        index += 1;
                        if index >= argv.len() {
                            return Err(format!("option -{ch} requires an argument"));
                        }
                        argv[index].clone()
                    };

                    match ch {
                        'p' => {
                            password = Some(PasswordSource::Arg(
                                value.to_string_lossy().into_owned(),
                            ));
                        }
                        'f' => password = Some(PasswordSource::File(PathBuf::from(value))),
                        'd' => {
                            let parsed = value
                                .to_string_lossy()
                                .parse::<u32>()
                                .map_err(|_| format!("invalid file descriptor: {value:?}"))?;
                            password = Some(PasswordSource::Fd(parsed));
                        }
                        'P' => prompt = Some(value.to_string_lossy().into_owned()),
                        _ => unreachable!(),
                    }
                    // The rest of this token was consumed as the value.
                    break;
                }
                other => return Err(format!("unknown option -{other}")),
            }
        }
        index += 1;
    }

    if index >= argv.len() {
        return Err("missing command".to_string());
    }

    let program = argv[index].clone();
    let args = argv[index + 1..].to_vec();

    Ok(ParseOutcome::Run(Cli {
        password: password.unwrap_or(PasswordSource::Stdin),
        prompt,
        verbose,
        program,
        args,
    }))
}

pub fn print_help() {
    println!("{USAGE}");
}

pub fn print_version() {
    println!("{VERSION}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Cli {
        match parse(args.iter().map(OsString::from)).expect("parse should succeed") {
            ParseOutcome::Run(cli) => cli,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn password_argument() {
        let cli = parse_ok(&["-p", "s3cret", "ssh", "root@host", "echo", "hi"]);
        assert_eq!(cli.password, PasswordSource::Arg("s3cret".into()));
        assert_eq!(cli.program, OsString::from("ssh"));
        assert_eq!(cli.args, vec![OsString::from("root@host"), OsString::from("echo"), OsString::from("hi")]);
    }

    #[test]
    fn attached_password_argument() {
        let cli = parse_ok(&["-ps3cret", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Arg("s3cret".into()));
        assert_eq!(cli.program, OsString::from("ssh"));
        assert_eq!(cli.args, vec![OsString::from("host")]);
    }

    #[test]
    fn password_from_env() {
        let cli = parse_ok(&["-e", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Env);
    }

    #[test]
    fn password_from_file() {
        let cli = parse_ok(&["-f", "pass.txt", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::File(PathBuf::from("pass.txt")));
        let cli = parse_ok(&["-fpass.txt", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::File(PathBuf::from("pass.txt")));
    }

    #[test]
    fn password_from_fd() {
        let cli = parse_ok(&["-d", "0", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Fd(0));
        let cli = parse_ok(&["-d7", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Fd(7));
    }

    #[test]
    fn prompt_and_verbose() {
        let cli = parse_ok(&["-P", "Password:", "-v", "-p", "x", "ssh", "host"]);
        assert_eq!(cli.prompt.as_deref(), Some("Password:"));
        assert!(cli.verbose);
    }

    #[test]
    fn password_defaults_to_stdin() {
        let cli = parse_ok(&["ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Stdin);
    }

    #[test]
    fn dash_dash_terminates_options() {
        let cli = parse_ok(&["-p", "x", "--", "-weird-program", "-arg"]);
        assert_eq!(cli.program, OsString::from("-weird-program"));
        assert_eq!(cli.args, vec![OsString::from("-arg")]);
    }

    #[test]
    fn program_may_start_with_dash_after_dash_dash() {
        let cli = parse_ok(&["--", "-p"]);
        assert_eq!(cli.program, OsString::from("-p"));
        assert!(cli.args.is_empty());
    }

    #[test]
    fn password_value_may_start_with_dash() {
        let cli = parse_ok(&["-p", "-secret", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Arg("-secret".into()));
    }

    #[test]
    fn clustered_flags() {
        let cli = parse_ok(&["-ve", "ssh", "host"]);
        assert!(cli.verbose);
        assert_eq!(cli.password, PasswordSource::Env);
    }

    #[test]
    fn help_and_version() {
        assert_eq!(parse([OsString::from("-h")]).unwrap(), ParseOutcome::Help);
        assert_eq!(parse([OsString::from("--help")]).unwrap(), ParseOutcome::Help);
        assert_eq!(parse([OsString::from("-V")]).unwrap(), ParseOutcome::Version);
        assert_eq!(parse([OsString::from("--version")]).unwrap(), ParseOutcome::Version);
    }

    #[test]
    fn errors() {
        assert!(parse(Vec::<OsString>::new()).is_err());
        assert!(parse([OsString::from("-p")]).is_err());
        assert!(parse([OsString::from("-f")]).is_err());
        assert!(parse([OsString::from("-d")]).is_err());
        assert!(parse([OsString::from("-P")]).is_err());
        assert!(parse([OsString::from("-z")]).is_err());
        assert!(parse([OsString::from("-d"), OsString::from("abc"), OsString::from("ssh")]).is_err());
    }

    #[test]
    fn last_password_option_wins() {
        let cli = parse_ok(&["-p", "one", "-e", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Env);
        let cli = parse_ok(&["-e", "-p", "two", "ssh", "host"]);
        assert_eq!(cli.password, PasswordSource::Arg("two".into()));
    }
}
