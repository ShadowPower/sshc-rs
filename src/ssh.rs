use crate::{
    config::{PortForward, Server},
    crypto,
};
use anyhow::{anyhow, Context, Result};
use log::warn;
use std::process::Command;

pub fn connect(server: &Server) -> Result<()> {
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
    cmd.arg("-tt");
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
    cmd.arg(format!("{}@{}", server.user, server.host));
    let password = server.password.clone().or_else(|| {
        server
            .password_encrypted
            .as_ref()
            .map(|enc| crypto::decrypt_password(enc))
    });
    execute_ssh(cmd, password)
}

fn execute_ssh(mut cmd: Command, password: Option<String>) -> Result<()> {
    if let Some(pass) = password.filter(|p| !p.is_empty()) {
        log::info!("正在建立 SSH 连接 (密码认证)...");
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
    } else {
        log::info!("正在建立 SSH 连接 (密钥认证)...");
    }
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
