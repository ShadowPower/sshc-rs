use crate::{config::Server, crypto};
use anyhow::{Context, Result, anyhow};
use log::warn;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use url::Url;

fn find_path() -> Result<PathBuf> {
    if let Ok(path) = which::which("filezilla") {
        return Ok(path);
    }
    let paths = if cfg!(target_os = "windows") {
        vec![
            "C:\\Program Files\\FileZilla FTP Client\\filezilla.exe",
            "C:\\Program Files (x86)\\FileZilla FTP Client\\filezilla.exe",
        ]
    } else if cfg!(target_os = "macos") {
        vec!["/Applications/FileZilla.app/Contents/MacOS/filezilla"]
    } else {
        vec![]
    };
    paths
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("未能找到 FileZilla"))
}

pub fn connect(server: &Server) -> Result<()> {
    if server.host.is_empty() || server.user.is_empty() {
        return Err(anyhow!("连接失败：服务器配置不完整 (缺少主机或用户名)。"));
    }
    let path = find_path()?;
    let password = server.password.clone().or_else(|| {
        server
            .password_encrypted
            .as_ref()
            .map(|enc| crypto::decrypt_password(enc))
    });
    let mut url = Url::parse(&format!(
        "sftp://{}@{}:{}",
        server.user,
        server.host,
        server.port.unwrap_or(22)
    ))?;
    if let Some(pass) = password.filter(|p| !p.is_empty()) {
        url.set_password(Some(&pass))
            .map_err(|_| anyhow!("设置密码失败"))?;
    }
    log::info!("启动 FileZilla 连接到 {}@{}...", server.user, server.host);
    if server.keyfile.is_some() {
        warn!("检测到密钥文件配置。请在 FileZilla 中配置或使用 SSH 代理。");
    }
    Command::new(path)
        .arg(url.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("启动 FileZilla 失败")?;
    Ok(())
}
