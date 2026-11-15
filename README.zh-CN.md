<div align="center">

# sshpass-win

**Windows 上的原生 `sshpass` 替代品。**

给 `ssh`、`scp`、`sftp` 提供密码认证 —— 原生实现，不要 MSYS，不要 Cygwin，不依赖 pty。

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## 为什么

`sshpass` 是脚本里给 `ssh` 喂密码的标准做法。在 Windows 上它基本是个坑：

- 常见发行版是 **MSYS2/Cygwin 构建**，靠 pty 喂密码；而 Windows 原生 OpenSSH（`C:\Windows\System32\OpenSSH\ssh.exe`）不读 pty，于是**永久卡死**。
- 在受限环境（作业对象、沙箱、服务账户）里，Cygwin 运行时常常连启动都做不到：`fatal error - couldn't create signal pipe, Win32 error 5`。
- PowerShell → MSYS → `ssh` 多层传参还会吃掉路径里的反斜杠，`known_hosts` 和密钥直接失效。

`sshpass-win` 是单个原生可执行文件。对 OpenSSH，它利用客户端自带的 `SSH_ASKPASS` 钩子：让 `ssh` 反过来向我们索要密码，而不是对着终端索要。没有 pty，没有 shell 包装，没有运行时 DLL。对确实需要控制台的程序（`sftp` 等），退回原生 ConPTY 循环，复刻 sshpass 的 pty 行为和退出码。

## 安装

**Scoop**

```powershell
scoop bucket add zsyn666 https://github.com/zsyn666/sshpass-win
scoop install sshpass-win
```

**WinGet**（manifest PR 合并后）

```powershell
winget install zsyn666.sshpass-win
```

**安装器** — 从 [Releases](https://github.com/zsyn666/sshpass-win/releases) 下载
`sshpass-win-<version>-x64-setup.exe`。按用户安装到
`%LOCALAPPDATA%\Programs\sshpass-win`，并把该目录加入用户 `PATH`；卸载时自动移除。

**便携版** — 把 `sshpass.exe` 放到 `PATH` 上任意目录：

```powershell
Invoke-WebRequest https://github.com/zsyn666/sshpass-win/releases/latest/download/sshpass.exe -OutFile "$env:USERPROFILE\.local\bin\sshpass.exe"
```

**从源码**（需要 Rust）：

```powershell
cargo install --git https://github.com/zsyn666/sshpass-win --bin sshpass
```

要求 Windows 10 1809+（ConPTY）与 Windows OpenSSH 8.4+（`SSH_ASKPASS_REQUIRE`），系统默认自带。

## 用法

命令行与原版一致：

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

选项之后的参数原样透传，`ssh` 自己的配置、`ProxyJump`、连接复用、agent 全部照常生效。

| 行为 | 说明 |
|---|---|
| 退出码 | `0` 成功 · `1` 参数错误 · `2` 密码来源冲突 · `3` 运行时错误 · `5` 密码错误 · `6` 主机密钥未知 · 其他为子进程退出码（ssh 认证失败通常是 `255`）。 |
| stdin | 透传给子进程。未给 `-p/-e/-f/-d` 时，**第一行是密码**，其余继续透传。 |
| stdout / stderr | askpass 路径下原样继承，管道、重定向、`-t` 都正常。 |
| `-P` | 完全替换默认提示串（`assword`），与原版一致。 |
| `-v` | 输出与原版相同的 `SSHPASS: ...` 诊断，绝不打印密码。 |
| `-e` | 裸 `-e` 读 `SSHPASS`；`-eMYVAR` 读 `MYVAR`。带空格的 `-e MYVAR` 会把 `MYVAR` 当成命令，与 sshpass 1.10 一致。 |

## 工作原理

两套引擎，自动选择：

**`askpass`（`ssh`/`scp` 默认）** OpenSSH 8.4+ 支持 `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`：让辅助程序代替终端应答。`sshpass-win` 启动 `ssh` 时把自己设为该辅助程序，密码通过子进程环境传递。`ssh` 调用 `sshpass.exe "root@host's password: "`，我们把密码写到 stdout，认证照常继续。stdout 与 stderr 保持分离，不分配终端。

**`pty`（`sftp`、`ssh -t`/`-tt` 及其他控制台程序）** 分配 ConPTY，转发输出，用滚动扫描器识别密码提示。这是 sshpass 的原始模型，也复刻其错误策略：提示再次出现视为密码错误（退出 `5`），`The authenticity of host` 视为主机密钥未知（退出 `6`）。`sftp` 必须走这条：stdin 不是终端时它不会调用 askpass。

可用 `SSHPASS_RS_ENGINE=askpass|pty` 强制指定。`SSHPASS_RS_ENGINE=pty` 对所有命令给出与原版逐字节一致的 pty 行为。

## 与 sshpass 1.10 的逐命令对照

在 Linux 上本地编译 `sshpass 1.10`，与 `sshpass-win` 并排实测：

| 调用 | sshpass 1.10 | sshpass-win |
|---|---|---|
| `sshpass -h` | 帮助文本 | **完全一致** |
| `sshpass` / `sshpass -p x` | 打印帮助，退出 `0` | 一致 |
| `sshpass -V` | 版本 + 默认提示，退出 `0` | 同结构，版本/许可证为自有品牌，退出 `0` |
| `sshpass -p a -p b ssh` | `Conflicting password source`，退出 `2` | 一致 |
| `sshpass -f a -d 0 ssh` | `Conflicting password source`，退出 `2` | 一致 |
| `sshpass -q ssh` | `invalid option -- 'q'`，退出 `1` | 一致 |
| `sshpass -d` | `option requires an argument -- 'd'`，退出 `1` | 一致 |
| `sshpass --help` | `invalid option -- '-'`，退出 `1` | 一致 |
| `sshpass -e ssh`（未设置） | 报错，退出 `1`（1.10 会段错误） | 报错，退出 `1` |
| `sshpass -eMYVAR ssh`（未设置） | 指名 `MYVAR` 报错，退出 `1` | 一致 |
| `sshpass -d abc ssh -V` | `atoi` → stdin，退出 `0` | 一致 |
| `sshpass -d -1 ssh -V` | 无提示时退出 `0` | 一致 |
| `sshpass -p x -- -missing` | `Failed to run command`，退出 `3` | 一致 |
| `sshpass -p a -e ssh`（环境已设） | 冲突，退出 `2` | 一致 |
| `sshpass -P one -P two -p x ssh -V` | 最后一个 `-P` 生效，退出 `0` | 一致 |
| `sshpass -vv -p x ssh -V` | 详细输出，退出 `0` | 一致 |
| 命令之后的选项 | 透传给 ssh | 一致 |
| 密码正确 | 退出 `0` | 退出 `0` |
| 密码错误（默认重试） | 退出 `5` | 退出 `5` |
| 密码错误（`NumberOfPasswordPrompts=1`） | 退出 `255` | 退出 `255` |
| 主机密钥未知（pty） | 退出 `6` | 退出 `6` |
| 主机密钥变更 | ssh 的 `255` | ssh 的 `255` |
| 命令不存在 | `Failed to run command`，退出 `3` | 一致 |

有意保留的差异：

- `-V` 打印 sshpass-win 版本与 MIT 许可证，而非原版 GPL 声明。
- sshpass 1.10 在 `-e` 未设置变量时段错误；我们打印错误并退出 `1`。
- Windows 没有 POSIX 文件描述符。`-d 0` 是 stdin；其他值按"不可读描述符"处理，发送空密码——与 sshpass `read()` 失败时一致。
- `askpass` 路径看不到主机密钥提示，因为 ssh 在无终端时会自动接受未知密钥。需要原版的主机密钥拒绝行为时用 `SSHPASS_RS_ENGINE=pty`。
- `pty` 引擎会把 stdout 和 stderr 合并，因为 ConPTY 把两者都接到控制台；`askpass` 引擎保持分离，脚本里重定向 stderr 时优先用后者。

## 发布

推送 `v1.0.0` 这类 tag。`.github/workflows/release.yml` 会跑格式与测试门禁，构建
`sshpass.exe`、便携 zip 和 Inno Setup 安装器，发布并附 SHA-256 校验和，然后更新
`main` 上的 Scoop 与 WinGet manifest。

WinGet 上架是向 `microsoft/winget-pkgs` 提 PR：把具有 `public_repo` 权限的经典 PAT
存为仓库 secret `WINGET_TOKEN`，再手动运行 **Submit to WinGet** workflow 并填入版本号。
PR 合并后即可 `winget install zsyn666.sshpass-win`。

## 安全

- **`-p` 会把密码暴露在进程列表里**（与原版相同），优先用 `-e`、`-f` 或 stdin。
- 密码通过环境变量传给子进程，能被已经可以检查你进程的进程读到；原版的 pty 方案同等暴露。
- 密钥在 drop 时清零，终端回显中抹除，`-v` 下也不打印。
- 主机密钥确认提示会被**拒绝**，不会拿密码当 `yes`。请预先写入 `known_hosts`，或加 `-o StrictHostKeyChecking=accept-new`。

## 从源码构建

```powershell
git clone https://github.com/zsyn666/sshpass-win
cd sshpass-win
cargo build --release --bin sshpass
# target\release\sshpass.exe
```

`.cargo/config.toml` 已开启静态 CRT，产物是单个约 470 KB 的可执行文件，无需分发运行时。

## 测试

```console
$ cargo test --features test-helpers                          # 40 个单元 + 25 个 CLI 测试
$ cargo test --features test-helpers --test ssh_integration   # 13 个联机测试
```

联机测试默认跳过，需要提供目标机：

```powershell
$env:SSHPASS_TEST_HOST='10.0.0.1'; $env:SSHPASS_TEST_USER='root'
$env:SSHPASS_TEST_PASSWORD='...'
cargo test --features test-helpers --test ssh_integration -- --test-threads=1
```

覆盖两套引擎、四种密码来源、退出码 `0/3/5/6/7/255`、`-t`/`-tt`、主机密钥提示、错误密码快速失败、stdin 载荷、UTF-8、大输出、`scp`。

## 已知限制

- `-d` 实际只支持 `0`（stdin）；Windows 没有 POSIX 文件描述符表。
- 密码按 UTF-8 处理，非 UTF-8 字节序列无法表示。
- pty 引擎会把 stdin 上的裸 `LF` 转成 `CRLF`，因为控制台子进程只在 CR 时提交一行。
- `-P` 只用于选择应答哪个提示，不会改写提示文字。

## 许可证

[MIT](LICENSE)
