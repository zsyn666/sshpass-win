<div align="center">

# sshpass-win

**Windows 上的 `sshpass` 替代品。**

给 `ssh`、`scp`、`sftp` 提供密码认证 —— 原生实现，不要 MSYS，不要 Cygwin，不要 pty。

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## 为什么

`sshpass` 是脚本里给 `ssh` 喂密码的标准做法。在 Windows 上它基本是个坑：

- 常见发行版是 **MSYS2/Cygwin 构建**，靠 pty 喂密码；而 Windows 原生 OpenSSH（`C:\Windows\System32\OpenSSH\ssh.exe`）不读 pty，于是**永久卡死**。
- 在受限环境（作业对象、沙箱、服务账户）里，Cygwin 运行时常常连启动都做不到：`fatal error - couldn't create signal pipe, Win32 error 5`。
- PowerShell → MSYS → `ssh` 多层传参还会吃掉路径里的反斜杠，`known_hosts` 和密钥直接失效。

`sshpass-win` 是单个原生可执行文件。它利用 OpenSSH 自带的 `SSH_ASKPASS` 钩子：让 `ssh` 反过来向我们索要密码，而不是对着终端索要。没有 pty，没有 shell 包装，没有运行时 DLL。

## 安装

```powershell
Invoke-WebRequest https://github.com/<you>/sshpass-win/releases/latest/download/sshpass.exe -OutFile "$env:USERPROFILE\.local\bin\sshpass.exe"
```

或从源码安装（需要 Rust）：

```powershell
cargo install --git https://github.com/<you>/sshpass-win --bin sshpass
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

选项之后的参数原样透传，`ssh` 自己的配置、`ProxyJump`、连接复用、agent 全部照常生效。

| 行为 | 说明 |
|---|---|
| 退出码 | 子进程的退出码。用法错误为 `1`；认证失败是 `ssh` 的 `255`。 |
| stdin | 透传给子进程。未给 `-p/-e/-f/-d` 时，**第一行是密码**，其余继续透传。 |
| stdout / stderr | 原样继承，管道、重定向、`-t` 都正常。 |
| `-P` | 收窄提示匹配串（非英文或非标准提示时有用）。 |
| `-v` | 打印解析到的程序、引擎与密码来源，**绝不**打印密码。 |

## 工作原理

两套引擎，自动选择：

**`askpass`（`ssh`/`scp` 默认）** OpenSSH 8.4+ 支持 `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`：让一个辅助程序代替终端应答。`sshpass-win` 启动 `ssh` 时把自己设为该辅助程序，密码通过子进程环境传递。`ssh` 调用 `sshpass.exe "root@host's password: "`，我们把密码写到 stdout，认证照常继续。

**`pty`（`sftp` 及其他控制台程序的兜底）** 分配 ConPTY，转发输出，用滚动扫描器识别密码提示。与原版 `sshpass` 同一模型，也是 `sftp` 必需的：stdin 不是终端时它不会调用 askpass。

可用 `SSHPASS_RS_ENGINE=askpass|pty` 强制指定。

两种引擎下密码都不会出现在命令行；输入之后也会从转发输出中抹掉。

## 安全

- **`-p` 会把密码暴露在进程列表里**（与原版相同），优先用 `-e`、`-f` 或 stdin。
- 密码通过环境变量传给子进程，能被已经可以检查你进程的进程读到；原版的 pty 方案同等暴露。
- 密钥在 drop 时清零，转发输出中抹除，`-v` 下也不打印。
- 主机密钥确认提示会被**拒绝**，不会拿密码当 `yes`。请预先写入 `known_hosts`，或加 `-o StrictHostKeyChecking=accept-new`。

## 兼容性

| | |
|---|---|
| Windows | 10 1809+ / 11 / Server 2019+（x86-64） |
| OpenSSH | 8.4+（`C:\Windows\System32\OpenSSH\`） |
| 命令 | `ssh`、`scp`、`sftp` 及任意控制台程序 |
| MSYS2 / Cygwin | 不需要，且刻意规避 |
| 依赖 | 除 Windows UCRT 外无 |

服务器没有 SFTP 子系统时（路由、busybox/dropbear 常见），`scp` 需要加 `-O`。

## 从源码构建

```powershell
git clone https://github.com/<you>/sshpass-win
cd sshpass-win
cargo build --release --bin sshpass
# target\release\sshpass.exe
```

`.cargo/config.toml` 已开启静态 CRT，产物是单个约 460 KB 的可执行文件，无需分发运行时。

## 测试

```console
$ cargo test                          # 40 个单元 + 19 个 CLI 测试
$ cargo test --test ssh_integration   # 9 个联机测试（需显式配置）
```

联机测试默认跳过，需要提供目标机：

```powershell
$env:SSHPASS_TEST_HOST='10.0.0.1'; $env:SSHPASS_TEST_USER='root'
$env:SSHPASS_TEST_PASSWORD='...'
cargo test --test ssh_integration -- --test-threads=1
```

覆盖两套引擎、四种密码来源、退出码透传、stdin 载荷、UTF-8 与大输出、错误密码快速失败、`scp`。

## 已知限制

- `-d` 只接受 `0`（stdin）。Windows 没有可移植的"读文件描述符 N"。
- 密码按 UTF-8 处理，非 UTF-8 字节序列无法表示。
- pty 引擎会把 stdin 上的裸 `LF` 转成 `CRLF`，因为控制台子进程只在 CR 时提交一行。
- 不支持改写提示文字：`-P` 只用于选择应答哪个提示。

## 许可证

[MIT](LICENSE)
