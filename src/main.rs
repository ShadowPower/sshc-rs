use anyhow::{Result, anyhow};
use clap::{Args, Parser, Subcommand};
use config::{Config, ConfigManager};
use std::path::PathBuf;

mod cli_api;
mod config;
mod config_cli;
mod crypto;
mod doctor;
mod file_transfer;
mod filezilla;
mod filezilla_detector;
mod run_cmd;
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
    version = env!("SSHC_BUILD_VERSION"),
    about = "一个强大且易用的 SSH 连接管理器。",
    long_about = "一个集成了 TUI、Web UI、人类友好和机器友好 CLI 的 SSH 连接管理器。"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
struct RunCommandArgs {
    #[command(subcommand)]
    action: Option<RunAction>,
    /// 目标：服务器名称、@分组名、@@all
    target: Option<String>,
    /// 要执行的远程命令（支持多参数；建议在复杂命令前加 `--`）
    #[arg(
        value_name = "COMMAND",
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<String>,
    /// 并行执行（默认串行）
    #[arg(short, long)]
    parallel: bool,
}

#[derive(Subcommand, Debug)]
enum RunAction {
    /// 以 sudo 执行远程命令（优先免密 sudo，失败时尝试使用已保存的服务器密码）
    Sudo(RunTargetCommand),
}

#[derive(Args, Debug)]
struct RunTargetCommand {
    /// 目标：服务器名称、@分组名、@@all
    target: String,
    /// 要执行的远程命令（支持多参数；建议在复杂命令前加 `--`）
    #[arg(
        value_name = "COMMAND",
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<String>,
    /// 并行执行（默认串行）
    #[arg(short, long)]
    parallel: bool,
}

#[derive(Debug)]
struct RunRequest {
    target: String,
    command: String,
    parallel: bool,
    use_sudo: bool,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
struct TtyCommandArgs {
    #[command(subcommand)]
    action: Option<TtyAction>,
    /// 目标：服务器名称（必须精确匹配）
    target: Option<String>,
    /// 要交互式执行的远程命令（支持多参数；建议在复杂命令前加 `--`）
    #[arg(
        value_name = "COMMAND",
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum TtyAction {
    /// 以 sudo 交互式执行远程命令（强制分配 TTY，适合 vim、top 等程序）
    Sudo(TtyTargetCommand),
}

#[derive(Args, Debug)]
struct TtyTargetCommand {
    /// 目标：服务器名称（必须精确匹配）
    target: String,
    /// 要交互式执行的远程命令（支持多参数；建议在复杂命令前加 `--`）
    #[arg(
        value_name = "COMMAND",
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<String>,
}

#[derive(Debug)]
struct TtyRequest {
    target: String,
    command: String,
    use_sudo: bool,
}

impl RunCommandArgs {
    fn into_request(self) -> Result<RunRequest> {
        if let Some(action) = self.action {
            return Ok(match action {
                RunAction::Sudo(args) => RunRequest {
                    target: args.target,
                    command: args.command.join(" "),
                    parallel: args.parallel,
                    use_sudo: true,
                },
            });
        }

        let target = self
            .target
            .ok_or_else(|| anyhow!("缺少执行目标，请使用 `sshc run <target> <command...>`"))?;
        if self.command.is_empty() {
            return Err(anyhow!(
                "缺少远程命令，请使用 `sshc run <target> <command...>`"
            ));
        }

        Ok(RunRequest {
            target,
            command: self.command.join(" "),
            parallel: self.parallel,
            use_sudo: false,
        })
    }
}

impl TtyCommandArgs {
    fn into_request(self) -> Result<TtyRequest> {
        if let Some(action) = self.action {
            return Ok(match action {
                TtyAction::Sudo(args) => TtyRequest {
                    target: args.target,
                    command: args.command.join(" "),
                    use_sudo: true,
                },
            });
        }

        let target = self
            .target
            .ok_or_else(|| anyhow!("缺少执行目标，请使用 `sshc tty <target> <command...>`"))?;
        if self.command.is_empty() {
            return Err(anyhow!(
                "缺少远程命令，请使用 `sshc tty <target> <command...>`"
            ));
        }

        Ok(TtyRequest {
            target,
            command: self.command.join(" "),
            use_sudo: false,
        })
    }
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
    /// 检查本地环境、配置完整性与服务器连通性
    Doctor {
        /// 指定服务器名称。不提供则检查全部服务器。
        name: Option<String>,
    },
    /// 在一台或多台服务器上执行远程命令
    Run(RunCommandArgs),
    /// 在单台服务器上交互式执行远程命令（支持 vim、top 等 TTY 程序）
    Tty(TtyCommandArgs),
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
        Some(Commands::Doctor { name }) => doctor::run(&config_manager, name)?,
        Some(Commands::Run(args)) => {
            let request = args.into_request()?;
            if request.use_sudo {
                run_cmd::run_with_privilege(
                    &config_manager,
                    &request.target,
                    &request.command,
                    request.parallel,
                    true,
                )?
            } else {
                run_cmd::run(
                    &config_manager,
                    &request.target,
                    &request.command,
                    request.parallel,
                )?
            }
        }
        Some(Commands::Tty(args)) => {
            let request = args.into_request()?;
            run_cmd::run_interactive_with_privilege(
                &config_manager,
                &request.target,
                &request.command,
                request.use_sudo,
            )?
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, RunAction, TtyAction};
    use clap::Parser;

    #[test]
    fn run_command_keeps_legacy_syntax() {
        let cli = Cli::try_parse_from(["sshc", "run", "prod", "uname", "-a"]).expect("parse cli");
        match cli.command {
            Some(Commands::Run(args)) => {
                assert!(args.action.is_none());
                assert_eq!(args.target.as_deref(), Some("prod"));
                assert_eq!(args.command, vec!["uname", "-a"]);
                assert!(!args.parallel);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn run_command_supports_sudo_subcommand() {
        let cli = Cli::try_parse_from(["sshc", "run", "sudo", "prod", "systemctl", "status"])
            .expect("parse cli");
        match cli.command {
            Some(Commands::Run(args)) => match args.action {
                Some(RunAction::Sudo(sudo_args)) => {
                    assert_eq!(sudo_args.target, "prod");
                    assert_eq!(sudo_args.command, vec!["systemctl", "status"]);
                    assert!(!sudo_args.parallel);
                }
                _ => panic!("unexpected run action"),
            },
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn tty_command_keeps_legacy_style_target_and_command() {
        let cli =
            Cli::try_parse_from(["sshc", "tty", "prod", "vim", "/tmp/a.txt"]).expect("parse cli");
        match cli.command {
            Some(Commands::Tty(args)) => {
                assert!(args.action.is_none());
                assert_eq!(args.target.as_deref(), Some("prod"));
                assert_eq!(args.command, vec!["vim", "/tmp/a.txt"]);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn tty_command_supports_sudo_subcommand() {
        let cli = Cli::try_parse_from(["sshc", "tty", "sudo", "prod", "htop"]).expect("parse cli");
        match cli.command {
            Some(Commands::Tty(args)) => match args.action {
                Some(TtyAction::Sudo(sudo_args)) => {
                    assert_eq!(sudo_args.target, "prod");
                    assert_eq!(sudo_args.command, vec!["htop"]);
                }
                _ => panic!("unexpected tty action"),
            },
            _ => panic!("unexpected command"),
        }
    }
}
