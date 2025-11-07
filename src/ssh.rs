use crate::{
    config::{PortForward, Server},
    crypto,
};
use anyhow::{Context, Result, anyhow};
use log::warn;
use std::process::{Command, Stdio};

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
            let script = format!(
                "@echo off\r\necho {}\r\n(goto) 2>nul & del \"%~f0\"\r\n",
                pass
            );
            askpass_file.write_all(script.as_bytes())?;
        }
        #[cfg(not(windows))]
        {
            use std::fs;
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;
            let script = format!("#!/bin/sh\necho \"{}\"\nrm -- \"$0\"\n", pass);
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

    let password = server.password.clone().or_else(|| {
        server
            .password_encrypted
            .as_ref()
            .map(|enc| crypto::decrypt_password(enc))
    });

    let mut cmd = prepare_ssh_auth(cmd, password)?;

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
}

impl<'a> SshProcessBuilder<'a> {
    pub fn new(server: &'a Server, remote_command: &str) -> Self {
        Self {
            server,
            remote_command: remote_command.to_string(),
        }
    }

    /// 执行远程命令并捕获其标准输出。
    pub fn execute_for_output(&self) -> Result<std::process::Output> {
        let mut cmd = build_ssh_command_base(self.server)?;
        cmd.arg(&self.remote_command);

        let password = self.server.password.clone().or_else(|| {
            self.server
                .password_encrypted
                .as_ref()
                .map(|enc| crypto::decrypt_password(enc))
        });

        let mut cmd = prepare_ssh_auth(cmd, password)?;

        cmd.stdin(Stdio::null());
        cmd.output().context("执行远程命令失败")
    }

    /// 启动一个 SSH 子进程，用于 I/O 管道操作（上传/下载）。
    pub fn spawn_for_io(&self) -> Result<std::process::Child> {
        let mut cmd = build_ssh_command_base(self.server)?;
        cmd.arg(&self.remote_command);

        let password = self.server.password.clone().or_else(|| {
            self.server
                .password_encrypted
                .as_ref()
                .map(|enc| crypto::decrypt_password(enc))
        });

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
