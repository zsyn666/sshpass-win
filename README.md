<div align="center">

# sshpass-win

**A drop-in `sshpass` for Windows.**

Password authentication for `ssh`, `scp` and `sftp` — native, no MSYS, no Cygwin, no pty.

[![Platform](https://img.shields.io/badge/platform-windows-0078D6?logo=windows&logoColor=white)](#compatibility)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-CE422B?logo=rust&logoColor=white)](#building-from-source)
[![Tests](https://img.shields.io/badge/tests-68%20passing-2ea44f)](#testing)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## Why

`sshpass` is the standard way to feed a password to `ssh` from a script. On Windows it is a trap:

- The usual builds are **MSYS2/Cygwin binaries**. They feed the password through a pty — but Windows OpenSSH (`C:\Windows\System32\OpenSSH\ssh.exe`) does not read from a pty, so it **hangs forever**.
- Inside restricted environments (job objects, sandboxes, service accounts) the Cygwin runtime often cannot even start: `fatal error - couldn't create signal pipe, Win32 error 5`.
- Path and environment mangling between PowerShell → MSYS → `ssh` breaks `known_hosts` and key lookup.

`sshpass-win` is a single native executable. It uses OpenSSH's own `SSH_ASKPASS` hook to hand over the password, so `ssh` asks *us* instead of a terminal. No pty, no shell shims, no runtime DLLs.

## Install

**Scoop / manual** — drop the binary anywhere on `PATH`:

```powershell
Invoke-WebRequest https://github.com/<you>/sshpass-win/releases/latest/download/sshpass.exe -OutFile "$env:USERPROFILE\.local\bin\sshpass.exe"
```

**From source** (needs Rust):

```powershell
cargo install --git https://github.com/<you>/sshpass-win --bin sshpass
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
Usage: sshpass [-f|-d|-p|-e] [-hV] command parameters
  -f filename   Take password to use from file
  -d number     Use number as file descriptor for getting password (Windows: 0 only)
  -p password   Provide password as argument (security unwise)
  -e            Password is passed as env-var "SSHPASS"
  -P prompt     Which string should sshpass search for to detect a password prompt
  -v            Be verbose about what you're doing
  -h, --help    Show help
  -V, --version Show version
With no password option, the first line of stdin is used.
```

Anything after the options is executed verbatim, so `ssh` keeps its own flags, config, `ProxyJump`, multiplexing and agent behaviour.

| Behaviour | Detail |
|---|---|
| Exit code | The child's exit code. Usage errors exit `1`; auth failures are whatever `ssh` returns (`255`). |
| stdin | Forwarded to the child. With no `-p/-e/-f/-d`, the **first line is the password** and the rest is forwarded. |
| stdout / stderr | Inherited untouched — pipes, redirection and `-t` all behave normally. |
| `-P` | Narrows prompt detection to your string (useful for non-English or non-standard prompts). |
| `-v` | Prints the resolved program, engine and password source. **Never** the password. |

## How it works

Two engines, picked automatically:

**`askpass` — the default for `ssh` and `scp`.** OpenSSH 8.4+ honours `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`, calling a helper program instead of prompting on a terminal. `sshpass-win` launches `ssh` with itself as that helper, passing the secret through the child's environment. `ssh` invokes `sshpass.exe "root@host's password: "`, we print the password on stdout, and authentication proceeds exactly as it would interactively.

**`pty` — the fallback for `sftp` and any other console program.** A ConPTY is allocated, output is relayed, and a rolling scanner watches for a password prompt. This is the same model as original `sshpass`, and it is what `sftp` needs: it refuses to call the askpass helper when its stdin is not a terminal.

Force either one with `SSHPASS_RS_ENGINE=askpass|pty`.

Either way the password never appears on a command line, and after it is typed it is redacted from the relayed output.

## Security

- **`-p` puts the password in the process list.** Same as `sshpass`. Prefer `-e`, `-f`, or stdin.
- The password is passed to the child in an environment variable, which is visible to processes that can already inspect your process. `sshpass`'s pty approach has the same exposure.
- The secret is zeroed on drop, redacted from relayed output, and never logged — including under `-v`.
- Host-key confirmation prompts are **refused**, not answered with the password. Pre-add the key, or pass `-o StrictHostKeyChecking=accept-new`.

## Compatibility

| | |
|---|---|
| Windows | 10 1809+ / 11 / Server 2019+ (x86-64) |
| OpenSSH | 8.4+ (`C:\Windows\System32\OpenSSH\`) |
| Commands | `ssh`, `scp`, `sftp`, any console program |
| MSYS2 / Cygwin | Not required, and deliberately avoided |
| Dependencies | None beyond the Windows UCRT |

`scp` needs `-O` when the server has no SFTP subsystem (common on routers and busybox/dropbear targets).

## Building from source

```powershell
git clone https://github.com/<you>/sshpass-win
cd sshpass-win
cargo build --release --bin sshpass
# target\release\sshpass.exe
```

Static CRT is enabled in `.cargo/config.toml`, so the result is a single ~460 KB executable with no redistributables.

## Testing

```console
$ cargo test                      # 40 unit + 19 CLI tests
$ cargo test --test ssh_integration   # 9 live tests, opt-in
```

Live tests hit a real server and are skipped unless configured:

```powershell
$env:SSHPASS_TEST_HOST='10.0.0.1'; $env:SSHPASS_TEST_USER='root'
$env:SSHPASS_TEST_PASSWORD='...'
cargo test --test ssh_integration -- --test-threads=1
```

They cover askpass and pty engines, all four password sources, exit-code propagation, stdin payloads, UTF-8 and large output, wrong-password fast-failure, and `scp`.

## Limitations

- `-d` accepts only `0` (stdin). Windows has no portable "read from fd N".
- Passwords are UTF-8; non-UTF-8 byte sequences are not representable.
- The pty engine translates a bare `LF` on stdin to `CRLF`, because a console child only submits a line on CR.
- No `-P` prompt rewriting: the flag only selects which prompt to answer.

## License

[MIT](LICENSE)
