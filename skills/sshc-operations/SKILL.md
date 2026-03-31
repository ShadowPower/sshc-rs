---
name: sshc-operations
description: Operate and troubleshoot sshc-rs for SSH fleet management. Use when tasks involve adding or editing SSH targets, connecting to saved hosts, running commands on one host/group/all hosts, interactive TTY sessions, uploading or downloading files, checking environment issues with doctor, launching web UI, or importing/exporting sshc configuration.
---

# sshc Operations

Use this skill to execute sshc-rs tasks safely and predictably.

## Intent Routing (First Decision)

- Discover available hosts/groups: `sshc list` (or `sshc l`).
- Open SSH shell on one host: `sshc c <name>` (or plain `sshc` for interactive picker).
- Open SFTP/FileZilla workflow: `sshc f <name>` (or plain `sshc f` for interactive picker).
- Run non-interactive command and collect output: `sshc run <target> -- <cmd>`.
- Run interactive/full-screen program (`vim`, `top`, `less`, REPL): `sshc tty <name> -- <cmd>`.
- Run elevated command: `sshc run sudo <target> -- <cmd>` or `sshc tty sudo <name> -- <cmd>`.
- Upload/download files or directories: `sshc up ...` / `sshc down ...`.
- Manage saved hosts/groups: `sshc config ...`.
- Script/JSON integration: `sshc api ...` only when machine-readable output is required.
- Diagnose environment/network/config: `sshc doctor [name]`.
- Migrate config between machines: `sshc export` / `sshc import`.

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
  - All hosts: `all` or `*`
  - Fuzzy match: substring against host key or display name
- `tty` target supports only exact single host name. It rejects `@group`, `all`, `*`, and fuzzy names.
- `run` defaults to serial; add `-p/--parallel` for parallel execution.
- `run sudo` wraps command with privilege logic; `tty sudo` does interactive elevated execution.

## Syntax Guardrails

- Prefer explicit separator: `sshc run <target> -- <command ...>` and `sshc tty <name> -- <command ...>`.
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
