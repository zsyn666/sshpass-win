<div align="center">

# sshpass-win

**A drop-in `sshpass` for Windows.**

Password authentication for `ssh`, `scp` and `sftp` — native, no MSYS, no Cygwin, no pty required.

[![Platform](https://img.shields.io/badge/platform-windows-0078D6?logo=windows&logoColor=white)](#compatibility)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-CE422B?logo=rust&logoColor=white)](#building-from-source)
[![Tests](https://img.shields.io/badge/tests-78%20passing-2ea44f)](#testing)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## Why

`sshpass` is the standard way to feed a password to `ssh` from a script. On Windows it is a trap:

- The usual builds are **MSYS2/Cygwin binaries**. They feed the password through a pty — but Windows OpenSSH (`C:\Windows\System32\OpenSSH\ssh.exe`) does not read from a pty, so it **hangs forever**.
- Inside restricted environments (job objects, sandboxes, service accounts) the Cygwin runtime often cannot even start: `fatal error - couldn't create signal pipe, Win32 error 5`.
- Path and environment mangling between PowerShell → MSYS → `ssh` breaks `known_hosts` and key lookup.

`sshpass-win` is a single native executable. For OpenSSH it uses the client's own `SSH_ASKPASS` hook, so `ssh` asks *us* for the password instead of a terminal. No pty, no shell shims, no runtime DLLs. For programs that genuinely need a console (`sftp`, anything else), it falls back to a native ConPTY loop that reproduces sshpass's original pty behaviour and exit codes.

## Install

**Scoop**

```powershell
scoop bucket add zsyn666 https://github.com/zsyn666/sshpass-win
scoop install sshpass-win
```

**WinGet** (after the manifest PR is merged)

```powershell
winget install zsyn666.sshpass-win
```

**Installer** — downloads `sshpass-win-<version>-x64-setup.exe` from the
[releases page](https://github.com/zsyn666/sshpass-win/releases). It installs
per-user under `%LOCALAPPDATA%\Programs\sshpass-win` and adds that directory to
your user `PATH`; the uninstaller removes it again.

**Portable** — drop `sshpass.exe` anywhere on `PATH`:

```powershell
Invoke-WebRequest https://github.com/zsyn666/sshpass-win/releases/latest/download/sshpass.exe -OutFile "$env:USERPROFILE\.local\bin\sshpass.exe"
```

**From source** (needs Rust):

```powershell
cargo install --git https://github.com/zsyn666/sshpass-win --bin sshpass
```

Requires Windows 10 1809+ (for ConPTY) and Windows OpenSSH 8.4+ (for `SSH_ASKPASS_REQUIRE`). Both ship with Windows by default.

## Usage

The command line is the one you already know:

```console
$ sshpass -p 'hunter2' ssh root@10.0.0.1 "uptime"
$ sshpass -e scp file.txt root@10.0.0.1:/tmp/
$ sshpass -f ~/.pw sftp -b - root@10.0.0.1 < commands.txt
```

```
Usage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters
   -f filename   Take password to use from file.
   -d number     Use number as file descriptor for getting password.
   -p password   Provide password as argument (security unwise).
   -e[env_var]   Password is passed as env-var "env_var" if given, "SSHPASS" otherwise.
   With no parameters - password will be taken from stdin.

   -P prompt     Which string should sshpass search for to detect a password prompt.
   -v            Be verbose about what you're doing.
   -h            Show help (this screen).
   -V            Print version information.
At most one of -f, -d, -p or -e should be used.
```

Anything after the options is executed verbatim, so `ssh` keeps its own flags, config, `ProxyJump`, multiplexing and agent behaviour.

| Behaviour | Detail |
|---|---|
| Exit codes | `0` success · `1` invalid arguments · `2` conflicting password source · `3` runtime error · `5` incorrect password · `6` unknown host key · otherwise the child's code (`255` for ssh auth failures). |
| stdin | Forwarded to the child. With no `-p/-e/-f/-d`, the **first line is the password** and the rest is forwarded. |
| stdout / stderr | Inherited untouched on the askpass path — pipes, redirection and `-t` behave normally. |
| `-P` | Replaces the default prompt marker (`assword`), exactly like sshpass. |
| `-v` | Prints the same `SSHPASS: ...` diagnostics as sshpass, never the password. |
| `-e` | A bare `-e` reads `SSHPASS`; `-eMYVAR` reads `MYVAR`. The space form (`-e MYVAR`) treats `MYVAR` as the command, as in sshpass 1.10. |

## How it works

Two engines, picked automatically:

**`askpass` — default for `ssh` and `scp`.** OpenSSH 8.4+ honours `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`, calling a helper program instead of prompting on a terminal. `sshpass-win` launches `ssh` with itself as that helper, passing the secret through the child's environment. `ssh` invokes `sshpass.exe "root@host's password: "`, we print the password on stdout, and authentication proceeds exactly as it would interactively. stdout and stderr stay separate, and no terminal is allocated.

**`pty` — `sftp`, `ssh -t`/`-tt`, and any other console program.** A ConPTY is allocated, output is relayed, and a rolling scanner watches for the prompt. This is sshpass's original model, including its error policy: a repeated prompt means wrong password (exit `5`), and `The authenticity of host` means unknown host key (exit `6`). It is what `sftp` needs: it refuses to call the askpass helper when its stdin is not a terminal.

Force either one with `SSHPASS_RS_ENGINE=askpass|pty`. `SSHPASS_RS_ENGINE=pty` gives byte-for-byte original `sshpass` prompt handling for every command.

## Compatibility with sshpass 1.10

Tested side by side against a locally built `sshpass 1.10` on Linux:

| Invocation | sshpass 1.10 | sshpass-win |
|---|---|---|
| `sshpass -h` | usage text | **identical** |
| `sshpass` / `sshpass -p x` | usage, exit `0` | same |
| `sshpass -V` | version + default prompt, exit `0` | same shape, branded version, exit `0` |
| `sshpass -p a -p b ssh` | `Conflicting password source`, exit `2` | same |
| `sshpass -f a -d 0 ssh` | `Conflicting password source`, exit `2` | same |
| `sshpass -q ssh` | `invalid option -- 'q'`, exit `1` | same |
| `sshpass -d` | `option requires an argument -- 'd'`, exit `1` | same |
| `sshpass --help` | `invalid option -- '-'`, exit `1` | same |
| `sshpass -e ssh` (unset) | message, exit `1` (1.10 crashes here) | message, exit `1` |
| `sshpass -eMYVAR ssh` (unset) | message naming `MYVAR`, exit `1` | same |
| `sshpass -d abc ssh -V` | `atoi` → stdin, exit `0` | same |
| `sshpass -d -1 ssh -V` | exit `0` when no prompt occurs | same |
| `sshpass -p x -- -missing` | `Failed to run command`, exit `3` | same |
| `sshpass -p a -e ssh` (env set) | conflict, exit `2` | same |
| `sshpass -P one -P two -p x ssh -V` | last `-P` wins, exit `0` | same |
| `sshpass -vv -p x ssh -V` | verbose, exit `0` | same |
| options after the command | passed to ssh | same |
| correct password | exit `0` | exit `0` |
| wrong password, default prompt count | exit `5` | exit `5` |
| wrong password, `NumberOfPasswordPrompts=1` | exit `255` | exit `255` |
| unknown host key (pty) | exit `6` | exit `6` |
| changed host key | ssh's `255` | ssh's `255` |
| missing command | `Failed to run command`, exit `3` | same |

Known, deliberate differences:

- `-V` prints the sshpass-win version and MIT licence instead of the original GPL notice.
- sshpass 1.10 segfaults on `-e` with an unset variable; we print the error and exit `1`.
- Windows has no POSIX file descriptors. `-d 0` is stdin; any other value behaves like an unreadable descriptor and sends an empty password, exactly as sshpass does when `read()` fails.
- The `askpass` engine never sees a host-key prompt because ssh auto-accepts unknown keys without a terminal. Use `SSHPASS_RS_ENGINE=pty` when you need sshpass's exact host-key refusal behaviour.
- The `pty` engine merges stdout and stderr because ConPTY attaches both to the console. The `askpass` engine keeps them separate; prefer it for scripts that redirect stderr.

## Releasing

Push a tag such as `v1.0.0`. `.github/workflows/release.yml` runs the format and
test gates, builds `sshpass.exe`, the portable zip and the Inno Setup installer,
publishes them with SHA-256 checksums, then updates the Scoop and WinGet
manifests in `main`.

The WinGet listing is a pull request against `microsoft/winget-pkgs`. Add a
classic PAT with `public_repo` as the `WINGET_TOKEN` repository secret, then run
the **Submit to WinGet** workflow with the released version. After the PR is
merged, `winget install zsyn666.sshpass-win` works.

## Security

- **`-p` puts the password in the process list.** Same as `sshpass`. Prefer `-e`, `-f`, or stdin.
- The password is passed to the child in an environment variable, which is visible to processes that can already inspect your process. `sshpass`'s pty approach has the same exposure.
- The secret is zeroed on drop, redacted from terminal echo, and never logged — including under `-v`.
- Host-key confirmation prompts are **refused**, not answered with the password. Pre-add the key, or pass `-o StrictHostKeyChecking=accept-new`.

## Building from source

```powershell
git clone https://github.com/zsyn666/sshpass-win
cd sshpass-win
cargo build --release --bin sshpass
# target\release\sshpass.exe
```

Static CRT is enabled in `.cargo/config.toml`, so the result is a single ~470 KB executable with no redistributables.

## Testing

```console
$ cargo test --features test-helpers                  # 40 unit + 25 CLI tests
$ cargo test --features test-helpers --test ssh_integration   # 13 live tests
```

Live tests hit a real server and are skipped unless configured:

```powershell
$env:SSHPASS_TEST_HOST='10.0.0.1'; $env:SSHPASS_TEST_USER='root'
$env:SSHPASS_TEST_PASSWORD='...'
cargo test --features test-helpers --test ssh_integration -- --test-threads=1
```

They cover both engines, all four password sources, exit codes `0/3/5/6/7/255`, `-t`/`-tt`, host-key prompts, wrong-password fast-failure, stdin payloads, UTF-8, large output, and `scp`.

## Limitations

- `-d` accepts only `0` (stdin) in practice; Windows has no POSIX file-descriptor table.
- Passwords are UTF-8; non-UTF-8 byte sequences are not representable.
- The pty engine translates a bare `LF` on stdin to `CRLF`, because a console child only submits a line on CR.
- `-P` selects which prompt to answer; it does not rewrite the prompt text.

## License

[MIT](LICENSE)
