use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use config::{Config, ConfigManager};
use std::path::PathBuf;

mod cli_api;
mod config;
mod config_cli;
mod crypto;
mod file_transfer;
mod filezilla;
mod ssh;
mod transfer;
mod tui;
mod tutorial;
mod web;

// --- 静态文件嵌入 ---
#[derive(rust_embed::Embed)]
#[folder = "."]
#[include = "index.html"]
#[include = "TUTORIAL.md"]
struct Asset;

// --- 命令行接口定义 (CLI) ---
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "一个强大且易用的 SSH 连接管理器。",
    long_about = "一个集成了 TUI、Web UI、人类友好和机器友好 CLI 的 SSH 连接管理器。"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 通过 SSH 连接服务器 (不带名称则进入交互模式)
    #[command(alias = "c")]
    Connect { name: Option<String> },

    /// 通过 FileZilla 连接服务器 (不带名称则进入交互模式)
    #[command(alias = "f")]
    Filezilla { name: Option<String> },

    /// 以人类可读格式列出所有服务器（按分组）
    #[command(alias = "l")]
    List,

    /// 启动 Web UI 配置界面
    #[command(alias = "w")]
    Web {
        /// 绑定地址 (默认 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        /// 指定端口 (默认: 自动选择可用端口)
        #[arg(long)]
        port: Option<u16>,
        /// 不自动打开浏览器
        #[arg(long)]
        no_browser: bool,
    },

    /// [人类友好] 管理服务器配置
    #[command(subcommand, alias = "conf")]
    Config(config_cli::ConfigCommands),

    /// [机器友好] 通过 JSON API 管理配置
    #[command(subcommand)]
    Api(cli_api::ApiCommands),

    /// 导出所有配置为一条可移植的命令
    Export,

    /// 从字符串导入配置
    Import {
        /// 由 'export' 命令生成的 Base85 编码字符串
        data: String,
        /// 强制导入，不进行确认
        #[arg(short, long)]
        force: bool,
    },
    /// 上传文件或目录到服务器 (用法: sshc up <本地路径> <服务器:远程路径>)
    #[command(alias = "up")]
    Upload {
        /// 本地源文件或目录路径
        local_path: PathBuf,
        /// 远程目标，格式为 <服务器名称:远程路径>
        destination: String,
    },
    /// 从服务器下载文件或目录 (用法: sshc down <服务器:远程路径> <本地路径>)
    #[command(alias = "down")]
    Download {
        /// 远程源，格式为 <服务器名称:远程路径>
        source: String,
        /// 本地目标文件或目录路径
        local_path: PathBuf,
    },
    /// 显示详细的用法教程
    #[command(alias = "t")]
    Tutorial,
}

// --- 命令行列表 ---
fn list_servers(config: &Config) -> Result<()> {
    if config.servers.is_empty() {
        println!("未配置服务器。请使用 'sshc web' 或 'sshc config add' 添加。");
        return Ok(());
    }

    println!("可用的服务器:\n");

    let mut displayed_servers = std::collections::HashSet::new();

    // 1. 先按定义的顺序显示分组
    for group in &config.groups {
        println!("📂 分组: {}", group);
        let mut found = false;
        for (name, server) in &config.servers {
            if server.group.as_deref() == Some(group) {
                print_server_item(name, server);
                displayed_servers.insert(name);
                found = true;
            }
        }
        if !found {
            println!("  (空)");
        }
        println!();
    }

    // 2. 显示未分组或分组名不在 groups 列表中的服务器
    let mut ungrouped_found = false;
    for (name, server) in &config.servers {
        if !displayed_servers.contains(name) {
            if !ungrouped_found {
                println!("📂 未分组:");
                ungrouped_found = true;
            }
            print_server_item(name, server);
        }
    }

    if !ungrouped_found && config.groups.is_empty() && !config.servers.is_empty() {
        // 如果完全没有分组配置，也作为普通列表显示
        for (name, server) in &config.servers {
            print_server_item(name, server);
        }
    }

    Ok(())
}

fn print_server_item(name: &str, server: &config::Server) {
    let display = server
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    println!("  - {} ({})", display, name);
    if server.user.is_empty() || server.host.is_empty() {
        println!("    └─ (配置不完整)");
    } else {
        println!(
            "    └─ {}@{}:{}",
            server.user,
            server.host,
            server.port.unwrap_or(22)
        );
    }
}

fn connect_by_name(config: &Config, name: &str, use_filezilla: bool) -> Result<()> {
    let server = config
        .servers
        .get(name)
        .ok_or_else(|| anyhow!("错误: 未找到服务器 '{}'", name))?;
    if use_filezilla {
        filezilla::connect(server)?;
    } else {
        ssh::connect(server)?;
    }
    Ok(())
}

fn parse_remote_arg(arg: &str) -> Result<(String, String)> {
    match arg.find(':') {
        Some(i) => {
            let (name, path) = arg.split_at(i);
            // `path` 包含冒号，所以从第1个字符开始切片
            Ok((name.to_string(), path[1..].to_string()))
        }
        None => Err(anyhow!(
            "无效的远程参数格式 '{}'，应为 '<服务器名称>:<远程路径>'",
            arg
        )),
    }
}

// --- 主程序入口 ---
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Cli::parse();
    let config_manager = ConfigManager::new()?;

    match args.command {
        None => tui::interactive_connect(&config_manager, tui::ConnectMode::Ssh)?,
        Some(Commands::Connect { name }) => match name {
            Some(n) => connect_by_name(&config_manager.read()?, &n, false)?,
            None => tui::interactive_connect(&config_manager, tui::ConnectMode::Ssh)?,
        },
        Some(Commands::Filezilla { name }) => match name {
            Some(n) => connect_by_name(&config_manager.read()?, &n, true)?,
            None => tui::interactive_connect(&config_manager, tui::ConnectMode::Filezilla)?,
        },
        Some(Commands::List) => list_servers(&config_manager.read()?)?,
        Some(Commands::Web {
            bind,
            port,
            no_browser,
        }) => web::run_web_ui(bind, port, no_browser).await?,
        Some(Commands::Config(cmd)) => config_cli::handle_config_command(cmd, &config_manager)?,
        Some(Commands::Api(cmd)) => cli_api::handle_api_command(cmd, &config_manager)?,
        Some(Commands::Export) => transfer::export_config(&config_manager)?,
        Some(Commands::Import { data, force }) => {
            transfer::import_config(&config_manager, &data, force)?
        }
        Some(Commands::Upload {
            local_path,
            destination,
        }) => {
            let (name, remote_path) = parse_remote_arg(&destination)?;
            let config = config_manager.read()?;
            let server = config
                .servers
                .get(&name)
                .ok_or_else(|| anyhow!("未找到服务器: {}", name))?;
            file_transfer::upload(server, &local_path, &remote_path)?
        }
        Some(Commands::Download { source, local_path }) => {
            let (name, remote_path) = parse_remote_arg(&source)?;
            let config = config_manager.read()?;
            let server = config
                .servers
                .get(&name)
                .ok_or_else(|| anyhow!("未找到服务器: {}", name))?;
            file_transfer::download(server, &remote_path, &local_path)?
        }
        Some(Commands::Tutorial) => tutorial::show()?,
    }

    Ok(())
}
