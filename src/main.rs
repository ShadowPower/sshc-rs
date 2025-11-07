use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use config::{Config, ConfigManager};

mod cli_api;
mod config;
mod config_cli;
mod crypto;
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
        Some(Commands::Tutorial) => tutorial::show()?,
    }

    Ok(())
}
