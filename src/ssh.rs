use crate::{
    config::{PortForward, Server},
    crypto,
};
use anyhow::{Context, Result, anyhow};
use log::warn;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum RemotePrivilege {
    #[default]
    None,
    Sudo,
}

const SUDO_PASSWORD_ENV_NAME: &str = "SSHC_SUDO_PASSWORD";
const SUDO_ASKPASS_TEMP_PATTERN: &str = "\"${TMPDIR:-/tmp}/sshc-sudo-askpass.XXXXXX\"";

/// 构建一个基础的 SSH 命令，包含所有通用配置（用户、主机、端口、密钥等）。
fn build_ssh_command_base(server: &Server) -> Result<Command> {
    if server.host.is_empty() || server.user.is_empty() {
        return Err(anyhow!("连接失败：服务器配置不完整 (缺少主机或用户名)。"));
    }
    let mut cmd: Command;
    if let Some(prefix) = server
        .ssh_prefix_command
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        cmd = Command::new(prefix);
        cmd.arg("ssh");
    } else {
        cmd = Command::new("ssh");
    }

    cmd.args([
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "PasswordAuthentication=yes",
    ]);
    if let Some(port) = server.port {
        cmd.arg("-p").arg(port.to_string());
    }
    if let Some(keyfile) = &server.keyfile {
        cmd.arg("-i").arg(shellexpand::tilde(keyfile).to_string());
    }
    cmd.arg(format!("{}@{}", server.user, server.host));
    Ok(cmd)
}

/// 为 SSH 命令准备密码认证（如果需要）。
///
/// 这会创建 `SSH_ASKPASS` 脚本，并配置必要的环境变量。
/// 脚本被设置为在执行后自删除。
fn prepare_ssh_auth(mut cmd: Command, password: Option<String>) -> Result<Command> {
    if let Some(pass) = password.filter(|p| !p.is_empty()) {
        log::info!("正在配置 SSH 密码认证...");
        let mut builder = tempfile::Builder::new();
        #[cfg(windows)]
        builder.suffix(".bat");
        #[cfg(not(windows))]
        builder.suffix(".sh");
        let mut askpass_file = builder.tempfile()?;
        #[cfg(windows)]
        {
            use std::io::Write;
            let mut escaped_pass = String::with_capacity(pass.len() * 2);
            for c in pass.chars() {
                match c {
                    '%' => escaped_pass.push_str("%%"),
                    '^' => escaped_pass.push_str("^^"),
                    '&' => escaped_pass.push_str("^&"),
                    '<' => escaped_pass.push_str("^<"),
                    '>' => escaped_pass.push_str("^>"),
                    '|' => escaped_pass.push_str("^|"),
                    '@' => escaped_pass.push_str("^@"),
                    '"' => escaped_pass.push_str("^\""),
                    '(' => escaped_pass.push_str("^("),
                    ')' => escaped_pass.push_str("^)"),
                    '!' => escaped_pass.push_str("^!"), // 即使未开启延迟扩展，转义也是安全的
                    _ => escaped_pass.push(c),
                }
            }
            let script = format!(
                "@echo off\r\necho {}\r\n(goto) 2>nul & del \"%~f0\"\r\n",
                escaped_pass
            );
            askpass_file.write_all(script.as_bytes())?;
        }
        #[cfg(not(windows))]
        {
            use std::fs;
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;
            let script = format!(
                "#!/bin/sh\ncat <<'SSHC_PASSWORD_EOF'\n{}\nSSHC_PASSWORD_EOF\nrm -- \"$0\"\n",
                pass
            );
            askpass_file.write_all(script.as_bytes())?;
            let mut perms = fs::metadata(askpass_file.path())?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(askpass_file.path(), perms)?;
        }

        let (_, askpass_path) = askpass_file.keep().context("无法持久化临时 askpass 文件")?;

        cmd.env("DISPLAY", "1")
            .env("SSH_ASKPASS", &askpass_path)
            .env("SSH_ASKPASS_REQUIRE", "force");
    }
    Ok(cmd)
}

fn resolve_server_password(server: &Server) -> Option<String> {
    server.password.clone().or_else(|| {
        server
            .password_encrypted
            .as_ref()
            .map(|enc| crypto::decrypt_password(enc))
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn build_sudo_askpass_cleanup_command() -> String {
    format!(
        "rm -f \"$sudo_tmp_askpass\"; unset {}",
        SUDO_PASSWORD_ENV_NAME
    )
}

fn build_sudo_askpass_write_command() -> String {
    format!(
        concat!(
            "cat > \"$sudo_tmp_askpass\" <<'SSHC_SUDO_ASKPASS_EOF'\n",
            "#!/bin/sh\n",
            "printf '%s\\n' \"${}\"\n",
            "SSHC_SUDO_ASKPASS_EOF"
        ),
        SUDO_PASSWORD_ENV_NAME
    )
}

fn build_sudo_askpass_fallback_command(quoted_command: &str, quoted_password: &str) -> String {
    let cleanup = build_sudo_askpass_cleanup_command();
    [
        format!("{SUDO_PASSWORD_ENV_NAME}={quoted_password}"),
        format!("export {SUDO_PASSWORD_ENV_NAME}"),
        format!(
            "sudo_tmp_askpass=\"$(mktemp {})\" || exit 1",
            SUDO_ASKPASS_TEMP_PATTERN
        ),
        build_sudo_askpass_write_command(),
        format!("chmod 700 \"$sudo_tmp_askpass\" || {{ {cleanup}; exit 1; }}"),
        format!("trap '{cleanup}' EXIT HUP INT TERM"),
        format!("SUDO_ASKPASS=\"$sudo_tmp_askpass\" sudo -A -p '' /bin/sh -c {quoted_command}"),
        "sudo_rc=$?".to_string(),
        cleanup,
        "trap - EXIT HUP INT TERM".to_string(),
        "exit $sudo_rc".to_string(),
    ]
    .join("\n")
}

fn wrap_ssh_command_for_privilege(command: &str, sudo_password: Option<&str>) -> String {
    let cleaned = command.trim();
    if cleaned.is_empty() {
        return cleaned.to_string();
    }

    let quoted = shell_quote(cleaned);
    let quoted_password = shell_quote(sudo_password.unwrap_or_default());
    let sudo_no_password_command = format!("sudo -n /bin/sh -c {}", quoted);
    let sudo_askpass_fallback_command =
        build_sudo_askpass_fallback_command(&quoted, &quoted_password);
    let no_sudo_command = format!("/bin/sh -c {}", quoted);

    format!(
        concat!(
            "if command -v sudo >/dev/null 2>&1; then ",
            "if sudo -n true >/dev/null 2>&1; then {sudo_no_password_command}; ",
            "else {sudo_askpass_fallback_command}; fi; ",
            "else {no_sudo_command}; fi"
        ),
        sudo_no_password_command = sudo_no_password_command,
        sudo_askpass_fallback_command = sudo_askpass_fallback_command,
        no_sudo_command = no_sudo_command,
    )
}

pub fn connect(server: &Server) -> Result<()> {
    let mut cmd = build_ssh_command_base(server)?;
    cmd.arg("-tt"); // 交互式 TTY

    if server.x11_forwarding.unwrap_or(false) {
        cmd.arg("-X");
    }
    for fwd in &server.port_forwards {
        match fwd {
            PortForward::Local {
                local_port: Some(lp),
                remote_host,
                remote_port: Some(rp),
            } if !remote_host.is_empty() => {
                cmd.arg("-L").arg(format!("{}:{}:{}", lp, remote_host, rp));
            }
            PortForward::Remote {
                remote_port: Some(rp),
                local_host,
                local_port: Some(lp),
            } if !local_host.is_empty() => {
                cmd.arg("-R").arg(format!("{}:{}:{}", rp, local_host, lp));
            }
            PortForward::Dynamic {
                local_port: Some(lp),
            } => {
                cmd.arg("-D").arg(lp.to_string());
            }
            _ => warn!("忽略了一个不完整的端口转发规则。"),
        };
    }

    let mut cmd = prepare_ssh_auth(cmd, resolve_server_password(server))?;

    log::info!("正在建立交互式 SSH 连接...");
    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;
        Err(anyhow!("执行 ssh 失败: {}", cmd.exec()))
    }
    #[cfg(windows)]
    {
        cmd.status().context("执行 ssh 失败")?;
        Ok(())
    }
}

/// 一个用于文件传输的 SSH 进程构建器。
pub struct SshProcessBuilder<'a> {
    server: &'a Server,
    remote_command: String,
    privilege: RemotePrivilege,
}

impl<'a> SshProcessBuilder<'a> {
    pub fn new(server: &'a Server, remote_command: &str) -> Self {
        Self {
            server,
            remote_command: remote_command.to_string(),
            privilege: RemotePrivilege::None,
        }
    }

    pub fn with_sudo(mut self) -> Self {
        self.privilege = RemotePrivilege::Sudo;
        self
    }

    /// 启动一个 SSH 子进程，用于 I/O 管道操作（上传/下载）。
    pub fn spawn_for_io(&self) -> Result<std::process::Child> {
        let mut cmd = build_ssh_command_base(self.server)?;
        let password = resolve_server_password(self.server);
        let remote_command = match self.privilege {
            RemotePrivilege::None => self.remote_command.clone(),
            RemotePrivilege::Sudo => {
                wrap_ssh_command_for_privilege(&self.remote_command, password.as_deref())
            }
        };
        cmd.arg(remote_command);

        let mut cmd = prepare_ssh_auth(cmd, password)?;

        let child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("启动 SSH 子进程失败")?;

        Ok(child)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_sudo_askpass_fallback_command, shell_quote, wrap_ssh_command_for_privilege,
        SUDO_PASSWORD_ENV_NAME,
    };

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("echo 'hi'"), "'echo '\"'\"'hi'\"'\"''");
    }

    #[test]
    fn sudo_wrapper_prefers_non_interactive_sudo_and_falls_back_to_askpass() {
        let wrapped = wrap_ssh_command_for_privilege("systemctl restart nginx", Some("s3cr'et"));
        assert!(wrapped.contains("sudo -n true"));
        assert!(wrapped.contains("sudo -n /bin/sh -c 'systemctl restart nginx'"));
        assert!(wrapped.contains("SUDO_ASKPASS"));
        assert!(wrapped.contains("sudo_tmp_askpass=\"$(mktemp "));
        assert!(wrapped.contains(&format!("{SUDO_PASSWORD_ENV_NAME}='s3cr'\"'\"'et'")));
        assert!(wrapped.contains("trap 'rm -f \"$sudo_tmp_askpass\"; unset SSHC_SUDO_PASSWORD'"));
        assert!(wrapped.contains("/bin/sh -c 'systemctl restart nginx'"));
    }

    #[test]
    fn sudo_wrapper_uses_empty_password_consistently() {
        let wrapped = build_sudo_askpass_fallback_command("'id -u'", "''");
        assert!(wrapped.contains("SSHC_SUDO_PASSWORD=''"));
        assert!(wrapped.contains("sudo_rc=$?"));
    }
}
