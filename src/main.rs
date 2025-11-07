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

    /// 以人类可读格式列出所有服务器
    #[command(alias = "l")]
    List,

    /// 启动 Web UI 配置界面
    #[command(alias = "w")]
    Web,

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
    } else {
        println!("可用的服务器:");
        for (name, server) in &config.servers {
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
            if let Some(prefix) = &server.ssh_prefix_command {
                if !prefix.is_empty() {
                    println!("      ├─ Prefix: {}", prefix);
                }
            }
        }
    }
    Ok(())
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
        Some(Commands::Web) => web::run_web_ui().await?,
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
