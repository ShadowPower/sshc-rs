use crate::{ConfigManager, config::Server};
use anyhow::{Result, anyhow};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Summary {
    ok: usize,
    warn: usize,
    err: usize,
}

impl Summary {
    fn ok(&mut self, message: &str) {
        self.ok += 1;
        println!("  [OK]   {}", message);
    }

    fn warn(&mut self, message: &str) {
        self.warn += 1;
        println!("  [WARN] {}", message);
    }

    fn err(&mut self, message: &str) {
        self.err += 1;
        println!("  [ERR]  {}", message);
    }
}

pub fn run(manager: &ConfigManager, name: Option<String>) -> Result<()> {
    let config = manager.read()?;
    if config.servers.is_empty() {
        println!("未配置服务器。请先使用 'sshc config add' 或 'sshc web' 添加。");
        return Ok(());
    }

    let targets: Vec<(String, &Server)> = match name {
        Some(name) => {
            let server = config
                .servers
                .get(&name)
                .ok_or_else(|| anyhow!("未找到服务器: {}", name))?;
            vec![(name, server)]
        }
        None => config
            .servers
            .iter()
            .map(|(server_name, server)| (server_name.clone(), server))
            .collect(),
    };

    let mut summary = Summary::default();
    println!("=== 本地环境检查 ===");
    check_local_binary("ssh", true, &mut summary);
    check_local_binary("filezilla", false, &mut summary);
    println!();

    println!("=== 配置与连通性检查 ===");
    for (server_name, server) in targets {
        println!("[{}]", server_name);
        check_server(server, &mut summary);
        println!();
    }

    println!(
        "检查完成: {} OK, {} WARN, {} ERR",
        summary.ok, summary.warn, summary.err
    );

    if summary.err > 0 {
        return Err(anyhow!("doctor 检测到 {} 个错误", summary.err));
    }
    Ok(())
}

fn check_local_binary(binary: &str, required: bool, summary: &mut Summary) {
    match which::which(binary) {
        Ok(path) => summary.ok(&format!("本地命令 '{}' 可用: {}", binary, path.display())),
        Err(_) if required => summary.err(&format!("缺少必需命令 '{}'", binary)),
        Err(_) => summary.warn(&format!(
            "本地命令 '{}' 不存在（仅影响相关可选功能）",
            binary
        )),
    }
}

fn check_server(server: &Server, summary: &mut Summary) {
    if server.host.trim().is_empty() {
        summary.err("host 为空");
        return;
    }
    if server.user.trim().is_empty() {
        summary.err("user 为空");
        return;
    }

    let port = server.port.unwrap_or(22);
    if port == 0 {
        summary.err("port 不能为 0");
        return;
    }
    summary.ok(&format!(
        "配置完整: {}@{}:{}",
        server.user, server.host, port
    ));

    if let Some(keyfile) = server.keyfile.as_deref().filter(|s| !s.trim().is_empty()) {
        let expanded = shellexpand::tilde(keyfile);
        if Path::new(expanded.as_ref()).exists() {
            summary.ok(&format!("私钥文件存在: {}", expanded));
        } else {
            summary.warn(&format!("私钥文件不存在: {}", expanded));
        }
    } else {
        summary.warn("未配置私钥文件（将依赖 ssh-agent 或默认密钥）");
    }

    let addrs = match (server.host.as_str(), port).to_socket_addrs() {
        Ok(v) => v.collect::<Vec<_>>(),
        Err(e) => {
            summary.err(&format!("DNS/地址解析失败: {}", e));
            return;
        }
    };
    if addrs.is_empty() {
        summary.err("DNS/地址解析为空");
        return;
    }
    summary.ok(&format!("地址解析成功: {}", addrs[0]));

    let timeout = Duration::from_secs(2);
    let start = Instant::now();
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                let elapsed_ms = start.elapsed().as_millis();
                summary.ok(&format!("TCP 可达: {} ({} ms)", addr, elapsed_ms));
                return;
            }
            Err(e) => last_error = Some((addr, e)),
        }
    }

    if let Some((addr, e)) = last_error {
        summary.err(&format!("TCP 不可达: {} ({})", addr, e));
    } else {
        summary.err("TCP 不可达");
    }
}
