---
name: sshc-operations
description: Operate and troubleshoot sshc-rs for SSH fleet management. Use when tasks involve adding or editing SSH targets, connecting to saved hosts, running commands on one host/group/all hosts, interactive TTY sessions, uploading or downloading files, checking environment issues with doctor, launching web UI, or importing/exporting sshc configuration.
---

# sshc Operations

Use this skill to execute sshc-rs tasks safely and predictably.

## Working mode

1. Confirm the user goal first: connect, config change, remote command, transfer, diagnosis, or migration.
2. Select the narrowest command that solves the goal.
3. Show the exact command before destructive operations such as config removal.

## Command selection

Use these command families:

- `sshc` or `sshc c <name>` for direct SSH connection.
- `sshc f` for FileZilla/SFTP workflows.
- `sshc config add|edit|show|remove` for configuration lifecycle.
- `sshc run <target> -- <cmd>` for non-interactive command execution.
- `sshc run sudo <target> -- <cmd>` when elevated command execution is required.
- `sshc tty <name> -- <cmd>` for interactive programs (`vim`, `top`, `less`, REPL).
- `sshc up` / `sshc down` for file and directory transfer.
- `sshc w` for local web management UI.
- `sshc api list|get|set|rm` for script and JSON automation.
- `sshc doctor [name]` for environment or connectivity checks.
- `sshc export` / `sshc import` for migration.

## Target rules

Follow sshc target semantics exactly:

- Single host: `<server-name>`
- Group: `@<group-name>`
- All hosts: `all` or `*`
- `tty` supports only an exact single host name.

## Safe defaults

- Prefer `-P` (prompted password) over `--password` to avoid shell history leakage.
- Avoid printing secrets from config exports or raw JSON payloads.
- Use serial execution first for risky commands; use `-p/--parallel` only when the action is idempotent and blast radius is acceptable.
- Run `sshc doctor` before debugging complex failures.

## Troubleshooting order

1. Verify binary and syntax with `sshc --help`.
2. Run `sshc doctor` for local checks.
3. Run `sshc doctor <name>` for host-level checks.
4. Validate saved config with `sshc config show <name>`.
5. Retry using the smallest reproducer command.

## References

Read [references/command-recipes.md](references/command-recipes.md) for detailed syntax and ready-to-run examples.
