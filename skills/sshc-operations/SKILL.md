---
name: sshc-operations
description: Operate and troubleshoot sshc-rs for SSH fleet management. Use when tasks involve adding or editing SSH targets, connecting to saved hosts, running commands on one host/group/@@all targets, interactive TTY sessions, uploading or downloading files, checking environment issues with doctor, launching web UI, or importing/exporting sshc configuration.
---

# sshc Operations

Use this skill to execute sshc-rs tasks safely and predictably.

## Intent Routing (First Decision)

- Discover available hosts/groups: `sshc list` (or `sshc l`).
- Open SSH shell on one host: `sshc c <name>` (or plain `sshc` for interactive picker).
- Open SFTP/FileZilla workflow: `sshc f <name>` (or plain `sshc f` for interactive picker).
- Run non-interactive command and collect output: `sshc run <target> -- <cmd>`.
- Run interactive/full-screen program (`vim`, `top`, `less`, REPL): `sshc tty <name> -- <cmd>`.
- Upload/download files or directories: `sshc up ...` / `sshc down ...`.
- Manage saved hosts/groups: `sshc config ...`.
- Script/JSON integration: `sshc api ...` only when machine-readable output is required.
- Diagnose environment/network/config: `sshc doctor [name]`.
- Migrate config between machines: `sshc export` / `sshc import`.

## CRITICAL: Privilege Escalation with sudo

Many remote operations require elevated privileges. **You MUST automatically detect when a command needs sudo and use the `sudo` subcommand — never use bare `sudo` inside the remote command string.**

### When to use sudo

Use `sshc run sudo` or `sshc tty sudo` when the remote command involves ANY of the following:

- **Service management**: `systemctl start|stop|restart|reload|enable|disable <service>`, `service <name> start|stop|restart`
- **Package management**: `apt install|remove|update|upgrade`, `yum install|remove`, `dnf install|remove`, `pacman -S|-R`
- **System configuration**: editing files under `/etc/`, `/sys/`, `/proc/`, running `sysctl`, `hostnamectl`
- **File operations on protected paths**: reading/writing `/var/log/`, `/opt/`, `/usr/local/`, `/root/`
- **User/group management**: `useradd`, `usermod`, `groupadd`, `passwd`
- **Network configuration**: `iptables`, `ip route`, `ip link`, `firewall-cmd`, `ufw`
- **Disk/filesystem operations**: `mount`, `umount`, `fdisk`, `mkfs`, `fsck`
- **System control**: `reboot`, `shutdown`, `poweroff`, `init`
- **Docker/container operations**: `docker ...` (when Docker requires root), `systemctl restart docker`
- **Permission changes**: `chmod`, `chown` on system-owned files
- **Any command that would fail with "Permission denied" without root**

### Syntax

`sudo` is a **subcommand** of `run` and `tty`, NOT a flag or prefix:

```bash
# Correct — sudo as subcommand
sshc run sudo prod -- systemctl restart nginx
sshc run sudo @backend -p -- apt update
sshc tty sudo prod -- vim /etc/nginx/nginx.conf

# WRONG — never do this
sshc run prod -- sudo systemctl restart nginx    # ← will NOT work
sshc run prod -- systemctl restart nginx          # ← will fail with permission denied
```

### Decision rule

Before constructing any `sshc run` or `sshc tty` command, ask yourself: **"Would this command fail with 'Permission denied' if executed as a non-root user?"** If yes, insert `sudo` as the subcommand:

- Without sudo: `sshc run <target> -- <cmd>`
- With sudo:    `sshc run sudo <target> -- <cmd>`
- Without sudo: `sshc tty <name> -- <cmd>`
- With sudo:    `sshc tty sudo <name> -- <cmd>`

### Commands that do NOT need sudo

- Reading public info: `uname -a`, `hostname`, `date`, `uptime`, `whoami`, `id`
- Listing files you own: `ls`, `cat` on user-accessible files
- Checking service status (read-only): `systemctl status <service> --no-pager`
- Disk usage (read-only): `df -h`, `free -m`, `top`, `htop`
- User's own processes: `ps aux`, `pgrep`

## Default Workflow

1. Confirm user goal: connect, command execution, transfer, config change, diagnosis, or migration.
2. Select the narrowest command for that goal.
3. For target discovery, default to `sshc list` (never `api/config` by default).
4. Execute directly once target is clear.
5. Show the exact command before destructive operations.

## Command Semantics (From Runtime Behavior)

- `run` target supports:
  - Exact host name: `prod`
  - Group: `@backend`
  - All hosts: `@@all`
- `tty` target supports:
  - Exact single host name: `prod`
- `run` defaults to serial; add `-p/--parallel` for parallel execution.
- `run sudo` and `tty sudo` are subcommands that wrap the remote command with privilege escalation (passwordless sudo first, then falls back to saved server password). See **Privilege Escalation with sudo** section above for when to use them.

## Syntax Guardrails

- Prefer explicit separator: `sshc run <target> -- <command ...>` and `sshc tty <name> -- <command ...>`.
- **CRITICAL for Windows/Git Bash environments**: When running commands with forward slashes (`/`) in the command arguments (e.g., file paths like `/etc/os-release`), ALWAYS wrap the entire command in quotes to prevent Git Bash from incorrectly converting Unix paths to Windows paths:
  ```bash
  # WRONG on Windows/Git Bash - path gets mangled
  sshc run nas -- cat /etc/os-release
  # Result: cat: 'C:/Program Files/Git/etc/os-release': No such file

  # CORRECT - quote the entire command
  sshc run nas -- "cat /etc/os-release"
  ```
  This applies to ANY command containing forward slashes, including paths, flags, or other arguments.
- For command-like user requests ("看时间", "查磁盘", "重启服务"), execute directly via `sshc run ...`, not via config inspection.
- Transfer syntax:
  - Upload: `sshc up <local_path> <server:remote_path>`
  - Download: `sshc down <server:remote_path> <local_path>`
- Config lifecycle:
  - Add/Edit/Show/Remove: `sshc config add|edit|show|remove ...`
  - Group operations: `sshc config group list|add|rename|remove ...`
- JSON automation only:
  - `sshc api list|get|set|rm`

## Discovery and Preflight Policy

- When user asks to run a remote command (for example, "看看 nas 的时间"), do not preflight with `sshc config show` or `sshc api list`.
- Use `sshc list` only if target naming is uncertain.
- Then execute directly with `sshc run <target> -- <cmd>`.
- Example: `sshc list` then `sshc run nas -- date`.

## Safe Defaults

- Prefer `-P` (prompted password) over `--password` to avoid shell history leakage.
- Avoid exposing secrets from `api get`, import/export payloads, or config fields.
- Use serial execution for risky operations (service restart, file mutation, package changes).
- Use `-p/--parallel` only for idempotent and low-blast-radius tasks (read-only checks, status collection).
- For potentially destructive remote commands, ask for confirmation and target scope first.

## Troubleshooting Order

1. Verify command syntax: `sshc --help` or subcommand `--help`.
2. Validate target names with `sshc list`.
3. Run `sshc doctor` (or `sshc doctor <name>`) for environment and reachability.
4. Retry with the smallest reproducer command (single host, simple command).
5. Use `sshc config show <name>` only for config debugging.
6. Use `sshc api get <name>` only when JSON inspection is explicitly required.

## References

Read [references/command-recipes.md](references/command-recipes.md) for detailed syntax and ready-to-run examples.
