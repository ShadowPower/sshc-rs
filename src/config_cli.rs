use crate::config::{PortForward, Server};
use crate::{crypto, ConfigManager};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use std::io::{self, Write};

#[derive(Subcommand, Debug)]
#[command(verbatim_doc_comment)]
pub enum ConfigCommands {
    /// 显示服务器的详细配置
    #[command(alias = "s")]
    Show {
        /// 服务器的唯一名称
        name: String,
    },
    /// 添加一个新服务器
    #[command(alias = "a")]
    Add {
        /// 服务器的唯一名称 (例如 'my-server')
        name: String,
        #[command(flatten)]
        server_args: ServerArgs,
    },
    /// 编辑一个已存在的服务器
    #[command(alias = "e")]
    Edit {
        /// 要编辑的服务器名称
        name: String,
        #[command(flatten)]
        server_args: ServerArgs,
    },
    /// 删除一个服务器
    #[command(alias = "rm")]
    Remove {
        /// 要删除的服务器名称
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct ServerArgs {
    #[arg(short = 'h', long, help = "主机名或 IP 地址")]
    host: Option<String>,
    #[arg(short = 'u', long, help = "用户名")]
    user: Option<String>,
    #[arg(short = 'p', long, help = "端口号")]
    port: Option<u16>,
    #[arg(short = 'n', long, help = "显示名称 (可选)")]
    display_name: Option<String>,
    #[arg(short = 'i', long = "key", help = "私钥文件路径")]
    keyfile: Option<String>,
    #[arg(long, help = "直接提供密码 (不安全)")]
    password: Option<String>,
    #[arg(
        short = 'P',
        long,
        help = "交互式输入密码 (安全)",
        conflicts_with = "password"
    )]
    ask_pass: bool,
    #[arg(long, help = "以明文形式存储密码 (不推荐)")]
    store_plaintext: bool,
    #[arg(short = 'L', long = "local-forward", help = "本地端口转发 (格式: LPORT:RHOST:RPORT)", value_parser = parse_local_forward)]
    local_forwards: Vec<PortForward>,
    #[arg(short = 'R', long = "remote-forward", help = "远程端口转发 (格式: RPORT:LHOST:LPORT)", value_parser = parse_remote_forward)]
    remote_forwards: Vec<PortForward>,
    #[arg(short = 'D', long = "dynamic-forward", help = "动态 SOCKS 转发 (格式: LPORT)", value_parser = parse_dynamic_forward)]
    dynamic_forwards: Vec<PortForward>,
    #[arg(short = 'X', long, help = "启用 X11 转发")]
    x11: bool,
    #[arg(short = 'x', long, help = "SSH 前缀命令 (例如: trzsz)")]
    prefix: Option<String>,
}

fn parse_local_forward(s: &str) -> Result<PortForward, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err("格式应为 LPORT:RHOST:RPORT".to_string());
    }
    Ok(PortForward::Local {
        local_port: Some(
            parts[0]
                .parse()
                .map_err(|e| format!("无效的本地端口: {}", e))?,
        ),
        remote_host: parts[1].to_string(),
        remote_port: Some(
            parts[2]
                .parse()
                .map_err(|e| format!("无效的远程端口: {}", e))?,
        ),
    })
}

fn parse_remote_forward(s: &str) -> Result<PortForward, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err("格式应为 RPORT:LHOST:LPORT".to_string());
    }
    Ok(PortForward::Remote {
        remote_port: Some(
            parts[0]
                .parse()
                .map_err(|e| format!("无效的远程端口: {}", e))?,
        ),
        local_host: parts[1].to_string(),
        local_port: Some(
            parts[2]
                .parse()
                .map_err(|e| format!("无效的本地端口: {}", e))?,
        ),
    })
}

fn parse_dynamic_forward(s: &str) -> Result<PortForward, String> {
    Ok(PortForward::Dynamic {
        local_port: Some(s.parse().map_err(|e| format!("无效的本地端口: {}", e))?),
    })
}

pub fn handle_config_command(cmd: ConfigCommands, manager: &ConfigManager) -> Result<()> {
    match cmd {
        ConfigCommands::Show { name } => show_server(name, manager)?,
        ConfigCommands::Add { name, server_args } => add_server(name, server_args, manager)?,
        ConfigCommands::Edit { name, server_args } => edit_server(name, server_args, manager)?,
        ConfigCommands::Remove { name } => remove_server(name, manager)?,
    }
    Ok(())
}

fn show_server(name: String, manager: &ConfigManager) -> Result<()> {
    let config = manager.read()?;
    let server = config
        .servers
        .get(&name)
        .ok_or_else(|| anyhow!("未找到服务器: {}", name))?;

    println!(
        "[{}] - {}",
        name,
        server.display_name.as_deref().unwrap_or("N/A")
    );
    println!("  Host           : {}", server.host);
    println!("  User           : {}", server.user);
    println!(
        "  Port           : {}",
        server
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "22".to_string())
    );
    println!(
        "  Keyfile        : {}",
        server.keyfile.as_deref().unwrap_or("N/A")
    );
    println!(
        "  Password       : {}",
        if server.password.is_some() || server.password_encrypted.is_some() {
            "已设置"
        } else {
            "未设置"
        }
    );
    println!(
        "  X11 Forwarding : {}",
        server.x11_forwarding.unwrap_or(false)
    );
    println!(
        "  Prefix Command : {}",
        server.ssh_prefix_command.as_deref().unwrap_or("N/A")
    );
    if !server.port_forwards.is_empty() {
        println!("  Port Forwards  :");
        for pf in &server.port_forwards {
            match pf {
                PortForward::Local {
                    local_port,
                    remote_host,
                    remote_port,
                } => println!(
                    "    - Local : localhost:{} -> {}:{}",
                    local_port.unwrap_or(0),
                    remote_host,
                    remote_port.unwrap_or(0)
                ),
                PortForward::Remote {
                    remote_port,
                    local_host,
                    local_port,
                } => println!(
                    "    - Remote: remote:{} -> {}:{}",
                    remote_port.unwrap_or(0),
                    local_host,
                    local_port.unwrap_or(0)
                ),
                PortForward::Dynamic { local_port } => println!(
                    "    - Dynamic: SOCKS proxy on localhost:{}",
                    local_port.unwrap_or(0)
                ),
            }
        }
    }
    Ok(())
}

fn add_server(name: String, args: ServerArgs, manager: &ConfigManager) -> Result<()> {
    let mut config = manager.read()?;
    if config.servers.contains_key(&name) {
        return Err(anyhow!(
            "服务器 '{}' 已存在。请使用 'edit' 命令修改。",
            name
        ));
    }
    let host = args
        .host
        .clone()
        .ok_or_else(|| anyhow!("添加新服务器时必须提供 --host"))?;
    let user = args
        .user
        .clone()
        .ok_or_else(|| anyhow!("添加新服务器时必须提供 --user"))?;

    let mut server = Server {
        host,
        user,
        ..Default::default()
    };
    apply_args_to_server(&mut server, args)?;

    config.servers.insert(name.clone(), server);
    manager.write(&config).with_context(|| "写入配置失败")?;
    println!("成功添加服务器 '{}'。", name);
    Ok(())
}

fn edit_server(name: String, args: ServerArgs, manager: &ConfigManager) -> Result<()> {
    let mut config = manager.read()?;
    let server = config
        .servers
        .get_mut(&name)
        .ok_or_else(|| anyhow!("未找到要编辑的服务器: {}", name))?;

    apply_args_to_server(server, args)?;

    manager.write(&config).with_context(|| "写入配置失败")?;
    println!("成功编辑服务器 '{}'。", name);
    Ok(())
}

fn apply_args_to_server(server: &mut Server, args: ServerArgs) -> Result<()> {
    if let Some(host) = args.host {
        server.host = host;
    }
    if let Some(user) = args.user {
        server.user = user;
    }
    if let Some(port) = args.port {
        server.port = Some(port);
    }
    if let Some(dn) = args.display_name {
        server.display_name = Some(dn);
    }
    if let Some(kf) = args.keyfile {
        server.keyfile = Some(kf);
    }
    if let Some(prefix) = args.prefix {
        server.ssh_prefix_command = Some(prefix);
    }
    if args.x11 {
        server.x11_forwarding = Some(true);
    }

    let mut all_forwards = args.local_forwards;
    all_forwards.extend(args.remote_forwards);
    all_forwards.extend(args.dynamic_forwards);
    if !all_forwards.is_empty() {
        server.port_forwards = all_forwards;
    }

    let password = if args.ask_pass {
        Some(rpassword::prompt_password("请输入密码: ")?)
    } else {
        args.password
    };

    if let Some(pass) = password {
        if pass.is_empty() {
            server.password = None;
            server.password_encrypted = None;
        } else if args.store_plaintext {
            server.password = Some(pass);
            server.password_encrypted = None;
        } else {
            server.password = None;
            server.password_encrypted = Some(crypto::encrypt_password(&pass)?);
        }
    }
    Ok(())
}

fn remove_server(name: String, manager: &ConfigManager) -> Result<()> {
    let mut config = manager.read()?;
    if !config.servers.contains_key(&name) {
        return Err(anyhow!("未找到要删除的服务器: {}", name));
    }

    print!("确实要删除服务器 '{}' 吗？ [y/N] ", name);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().eq_ignore_ascii_case("y") {
        config.servers.remove(&name);
        manager.write(&config).with_context(|| "写入配置失败")?;
        println!("已删除服务器 '{}'。", name);
    } else {
        println!("已取消删除。");
    }
    Ok(())
}
