//! sshpass-compatible command line parsing.
//!
//! The grammar is the one sshpass 1.10 gives to getopt:
//!
//! ```text
//! getopt(argc, argv, "+f:d:p:P:he::Vv")
//! ```
//!
//! `+` stops option parsing at the first non-option, so `sshpass ssh -v host`
//! passes `-v` to ssh. `e::` makes the environment variable name optional and
//! attached only, so `-eMYVAR` names a variable and a bare `-e` means
//! `SSHPASS`.
//!
//! Errors are reported the way getopt and sshpass report them, and they carry
//! sshpass's exit code, so a caller cannot tell the two apart.

use std::ffi::OsString;
use std::path::PathBuf;

/// sshpass's built-in prompt marker (`PASSWORD_PROMPT` in configure.ac).
pub const PASSWORD_PROMPT: &str = "assword";
/// sshpass's default environment variable for `-e`.
pub const DEFAULT_ENV_PASSWORD: &str = "SSHPASS";

pub const USAGE: &str = "\
Usage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters
   -f filename   Take password to use from file.
   -d number     Use number as file descriptor for getting password.
   -p password   Provide password as argument (security unwise).
   -e[env_var]   Password is passed as env-var \"env_var\" if given, \"SSHPASS\" otherwise.
   With no parameters - password will be taken from stdin.

   -P prompt     Which string should sshpass search for to detect a password prompt.
   -v            Be verbose about what you're doing.
   -h            Show help (this screen).
   -V            Print version information.
At most one of -f, -d, -p or -e should be used.";

pub const VERSION_TEXT: &str = concat!(
    "sshpass ",
    env!("CARGO_PKG_VERSION"),
    " (sshpass-win, Rust)\n",
    "(C) 2026 zsyn666\n",
    "Compatible with sshpass 1.10 by Lingnu Open Source Consulting Ltd. and Shachar Shemesh\n",
    "This program is free software, and can be distributed under the terms of the MIT license\n",
    "See the LICENSE file for more information.\n",
    "\n",
    "Using \"assword\" as the default password prompt indicator."
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// No password option: the first line of stdin.
    Stdin,
    /// `-d number` (Windows: only 0, which is stdin).
    Fd(i64),
    /// `-f filename`
    File(PathBuf),
    /// `-p password`
    Arg(String),
    /// `-e` / `-eVAR`
    Env(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub password: PasswordSource,
    /// `-P` overrides the marker; otherwise [`PASSWORD_PROMPT`].
    pub prompt: String,
    /// `-v` may be repeated; sshpass only tests whether it is set.
    pub verbose: u8,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Run(Cli),
    Help,
    Version,
    /// sshpass prints the usage and succeeds when no command is given.
    NoCommand,
}

/// A parse failure that has already printed its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(pub i32);

pub fn parse<I>(argv: I) -> Result<Outcome, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let argv: Vec<OsString> = argv.into_iter().collect();
    let mut password: Option<PasswordSource> = None;
    let mut prompt = PASSWORD_PROMPT.to_string();
    let mut verbose = 0u8;
    let mut index = 0usize;

    while index < argv.len() {
        let Some(text) = argv[index].to_str() else {
            // A non-UTF-8 first token cannot be an option.
            break;
        };
        if text == "--" {
            index += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }

        let chars: Vec<char> = text.chars().skip(1).collect();
        let mut position = 0usize;
        while position < chars.len() {
            let option = chars[position];
            let attached: String = chars[position + 1..].iter().collect();

            match option {
                'v' => {
                    verbose = verbose.saturating_add(1);
                    position += 1;
                }
                'h' => return Ok(Outcome::Help),
                'V' => return Ok(Outcome::Version),
                'f' | 'd' | 'p' | 'P' => {
                    let value = if !attached.is_empty() {
                        OsString::from(attached)
                    } else {
                        index += 1;
                        match argv.get(index) {
                            Some(value) => value.clone(),
                            None => {
                                eprintln!("sshpass: option requires an argument -- '{option}'");
                                return Err(ParseError(1));
                            }
                        }
                    };
                    match option {
                        'P' => prompt = value.to_string_lossy().into_owned(),
                        'f' => {
                            claim(&mut password)?;
                            password = Some(PasswordSource::File(PathBuf::from(value)));
                        }
                        'd' => {
                            let number = atoi(&value.to_string_lossy());
                            claim(&mut password)?;
                            password = Some(PasswordSource::Fd(number));
                        }
                        'p' => {
                            claim(&mut password)?;
                            password =
                                Some(PasswordSource::Arg(value.to_string_lossy().into_owned()));
                        }
                        _ => unreachable!(),
                    }
                    // The rest of this token was the value.
                    break;
                }
                'e' => {
                    let name = if attached.is_empty() {
                        DEFAULT_ENV_PASSWORD.to_string()
                    } else {
                        attached
                    };
                    // sshpass reports the conflict first and the missing
                    // variable second, and the later error wins.
                    let conflicted = claim(&mut password).is_err();
                    password = Some(PasswordSource::Env(name.clone()));
                    if std::env::var_os(&name).is_none() {
                        eprintln!(
                            "sshpass: -e option given but \"{name}\" environment variable is not set."
                        );
                        return Err(ParseError(1));
                    }
                    if conflicted {
                        return Err(ParseError(2));
                    }
                    break;
                }
                other => {
                    eprintln!("sshpass: invalid option -- '{other}'");
                    return Err(ParseError(1));
                }
            }
        }
        index += 1;
    }

    if index >= argv.len() {
        return Ok(Outcome::NoCommand);
    }

    Ok(Outcome::Run(Cli {
        password: password.unwrap_or(PasswordSource::Stdin),
        prompt,
        verbose,
        program: argv[index].clone(),
        args: argv[index + 1..].to_vec(),
    }))
}

/// `atoi` from sshpass: leading whitespace and sign, then digits, stopping at
/// the first non-digit. No number means 0. sshpass does not reject garbage.
fn atoi(text: &str) -> i64 {
    let text = text.trim_start();
    let mut chars = text.chars().peekable();
    let mut sign = 1i64;
    if let Some(value) = chars.peek() {
        if *value == '-' {
            sign = -1;
            chars.next();
        } else if *value == '+' {
            chars.next();
        }
    }
    let mut value = 0i64;
    for ch in chars {
        let Some(digit) = ch.to_digit(10) else { break };
        value = value.saturating_mul(10).saturating_add(i64::from(digit));
    }
    sign.saturating_mul(value)
}

/// Report a second password source the way sshpass does and fail with its
/// "conflicting arguments" code.
fn claim(slot: &mut Option<PasswordSource>) -> Result<(), ParseError> {
    if slot.is_some() {
        eprintln!("Conflicting password source");
        return Err(ParseError(2));
    }
    Ok(())
}

pub fn print_usage() {
    println!("{USAGE}");
}

pub fn print_version() {
    println!("{VERSION_TEXT}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Cli {
        match parse(args.iter().map(OsString::from)).expect("parse should succeed") {
            Outcome::Run(cli) => cli,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn password_argument() {
        let cli = parse_ok(&["-p", "secret", "ssh", "root@host", "echo", "hi"]);
        assert_eq!(cli.password, PasswordSource::Arg("secret".into()));
        assert_eq!(cli.prompt, PASSWORD_PROMPT);
        assert_eq!(cli.program, OsString::from("ssh"));
        assert_eq!(
            cli.args,
            vec![
                OsString::from("root@host"),
                OsString::from("echo"),
                OsString::from("hi")
            ]
        );
    }

    #[test]
    fn attached_values() {
        assert_eq!(
            parse_ok(&["-psecret", "ssh"]).password,
            PasswordSource::Arg("secret".into())
        );
        assert_eq!(
            parse_ok(&["-fpass.txt", "ssh"]).password,
            PasswordSource::File(PathBuf::from("pass.txt"))
        );
        assert_eq!(parse_ok(&["-d0", "ssh"]).password, PasswordSource::Fd(0));
        assert_eq!(parse_ok(&["-Psecret", "ssh"]).prompt, "secret");
    }

    #[test]
    fn environment_source_with_and_without_name() {
        std::env::set_var("SSHPASS", "x");
        std::env::set_var("MY_SSH_PW", "x");
        assert_eq!(
            parse_ok(&["-e", "ssh"]).password,
            PasswordSource::Env("SSHPASS".into())
        );
        assert_eq!(
            parse_ok(&["-eMY_SSH_PW", "ssh"]).password,
            PasswordSource::Env("MY_SSH_PW".into())
        );
        std::env::remove_var("SSHPASS");
        std::env::remove_var("MY_SSH_PW");
    }

    #[test]
    fn stdin_is_the_default_source() {
        assert_eq!(parse_ok(&["ssh", "host"]).password, PasswordSource::Stdin);
    }

    #[test]
    fn options_stop_at_the_command() {
        // sshpass uses getopt("+..."), so ssh's own flags are not ours.
        let cli = parse_ok(&["-p", "x", "ssh", "-v", "host"]);
        assert_eq!(cli.args, vec![OsString::from("-v"), OsString::from("host")]);
        assert_eq!(cli.verbose, 0);
    }

    #[test]
    fn verbose_accumulates() {
        assert_eq!(parse_ok(&["-vv", "-p", "x", "ssh"]).verbose, 2);
    }

    #[test]
    fn double_dash_terminates_options() {
        let cli = parse_ok(&["-p", "x", "--", "-weird", "-arg"]);
        assert_eq!(cli.program, OsString::from("-weird"));
        assert_eq!(cli.args, vec![OsString::from("-arg")]);
    }

    #[test]
    fn help_version_and_no_command() {
        assert_eq!(parse([OsString::from("-h")]).unwrap(), Outcome::Help);
        assert_eq!(parse([OsString::from("-V")]).unwrap(), Outcome::Version);
        assert_eq!(parse(Vec::new()).unwrap(), Outcome::NoCommand);
        assert_eq!(
            parse([OsString::from("-p"), OsString::from("x")]).unwrap(),
            Outcome::NoCommand
        );
    }

    #[test]
    fn conflicting_sources_exit_two() {
        assert_eq!(
            parse([
                OsString::from("-p"),
                OsString::from("a"),
                OsString::from("-p"),
                OsString::from("b"),
                OsString::from("ssh")
            ]),
            Err(ParseError(2))
        );
        assert_eq!(
            parse([
                OsString::from("-f"),
                OsString::from("a"),
                OsString::from("-d"),
                OsString::from("0"),
                OsString::from("ssh")
            ]),
            Err(ParseError(2))
        );
    }

    #[test]
    fn missing_environment_variable_exits_one() {
        std::env::remove_var("NOT_SET_ANYWHERE");
        assert_eq!(
            parse([OsString::from("-eNOT_SET_ANYWHERE"), OsString::from("ssh")]),
            Err(ParseError(1))
        );
    }

    #[test]
    fn invalid_option_exits_one() {
        assert_eq!(parse([OsString::from("-q")]), Err(ParseError(1)));
    }

    #[test]
    fn missing_option_value_exits_one() {
        for flag in ["-f", "-d", "-p", "-P"] {
            assert_eq!(parse([OsString::from(flag)]), Err(ParseError(1)), "{flag}");
        }
    }

    #[test]
    fn fd_uses_atoi_semantics() {
        assert_eq!(
            parse_ok(&["-d", "0", "ssh"]).password,
            PasswordSource::Fd(0)
        );
        assert_eq!(
            parse_ok(&["-d", "abc", "ssh"]).password,
            PasswordSource::Fd(0)
        );
        assert_eq!(
            parse_ok(&["-d", "12x", "ssh"]).password,
            PasswordSource::Fd(12)
        );
        assert_eq!(
            parse_ok(&["-d", "-1", "ssh"]).password,
            PasswordSource::Fd(-1)
        );
        assert_eq!(
            parse_ok(&["-d", "  +7", "ssh"]).password,
            PasswordSource::Fd(7)
        );
    }

    #[test]
    fn usage_text_matches_sshpass() {
        assert!(USAGE.starts_with("Usage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters"));
        assert!(USAGE.ends_with("At most one of -f, -d, -p or -e should be used."));
        assert!(
            VERSION_TEXT.contains("Using \"assword\" as the default password prompt indicator.")
        );
    }
}
