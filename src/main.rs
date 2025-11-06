use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use clap::{Parser, Subcommand};
use log::warn;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

mod api;
mod config_cli;
mod transfer;
mod tui;
mod tutorial;

// --- 静态文件嵌入 ---
#[derive(Embed)]
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
    Api(api::ApiCommands),

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

// --- Serde 辅助模块 ---
mod serde_helpers {
    use serde::{self, Deserialize, Deserializer};
    pub fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            String(String),
            Int(u16),
        }

        match StringOrInt::deserialize(deserializer)? {
            StringOrInt::String(s) if s.is_empty() => Ok(None),
            StringOrInt::String(s) => s.parse::<u16>().map(Some).map_err(serde::de::Error::custom),
            StringOrInt::Int(i) => Ok(Some(i)),
        }
    }
}

// --- 统一的数据结构 ---

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub servers: BTreeMap<String, Server>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct Server {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x11_forwarding: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_prefix_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_encrypted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_password_as_plaintext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_password_encrypted: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum PortForward {
    Local {
        #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
        local_port: Option<u16>,
        #[serde(default)]
        remote_host: String,
        #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
        remote_port: Option<u16>,
    },
    Remote {
        #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
        remote_port: Option<u16>,
        #[serde(default)]
        local_host: String,
        #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
        local_port: Option<u16>,
    },
    Dynamic {
        #[serde(deserialize_with = "serde_helpers::empty_string_as_none")]
        local_port: Option<u16>,
    },
}

// --- 配置管理器 ---
pub struct ConfigManager {
    path: PathBuf,
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("无法获取用户主目录"))?;
        let config_dir = home_dir.join(".sshc");
        Ok(Self {
            path: config_dir.join("config.toml"),
        })
    }

    pub fn ensure_exists(&self) -> Result<()> {
        let dir = self.path.parent().unwrap();
        fs::create_dir_all(dir).with_context(|| format!("无法创建配置目录: {:?}", dir))?;
        if !self.path.exists() {
            let default_config = Config::default();
            fs::write(&self.path, toml::to_string(&default_config)?)
                .with_context(|| format!("无法创建默认配置文件: {:?}", self.path))?;
        }
        Ok(())
    }

    pub fn read(&self) -> Result<Config> {
        self.ensure_exists()?;
        let content = fs::read_to_string(&self.path)?;
        toml::from_str(&content).with_context(|| "解析 TOML 配置文件失败")
    }

    pub fn write(&self, config: &Config) -> Result<()> {
        self.ensure_exists()?;
        fs::write(&self.path, toml::to_string_pretty(config)?)
            .with_context(|| format!("无法写入配置文件: {:?}", self.path))
    }
}

// --- 加密模块 ---
pub mod crypto {
    use anyhow::{Result, anyhow};
    use fernet::Fernet;
    use log::warn;
    const ENCRYPTION_KEY_B64: &str = "OPwdflh9vDTVrt5ulyGE6UmHvSMVf0Vc3jxrqAMak_Q=";
    fn get_cipher() -> Result<Fernet> {
        Fernet::new(ENCRYPTION_KEY_B64).ok_or_else(|| anyhow!("无效的加密密钥"))
    }
    pub fn encrypt_password(password: &str) -> Result<String> {
        Ok(get_cipher()?.encrypt(password.as_bytes()))
    }
    pub fn decrypt_password(encrypted: &str) -> String {
        match get_cipher() {
            Ok(cipher) => match cipher.decrypt(encrypted) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => {
                    warn!("无法解密密码，可能它是明文或无效的。");
                    encrypted.to_string()
                }
            },
            Err(_) => encrypted.to_string(),
        }
    }
}

// --- SSH 连接逻辑 ---
pub mod ssh {
    use super::{PortForward, Server, crypto};
    use anyhow::{Context, Result, anyhow};
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
}

// --- FileZilla 集成 ---
pub mod filezilla {
    use super::{Server, crypto};
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
}

// --- Web UI 后端 ---
async fn run_web_ui() -> Result<()> {
    let config_manager = Arc::new(Mutex::new(ConfigManager::new()?));
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/servers", get(get_servers))
        .route("/api/server", post(save_server))
        .route("/api/server/{name}", delete(delete_server))
        .with_state(config_manager);
    let port = portpicker::pick_unused_port().context("无法找到可用端口")?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("正在启动 Web UI... 请在浏览器中打开以下任一地址:");
    if let Ok(hostname) = hostname::get() {
        if let Ok(hostname_str) = hostname.into_string() {
            println!("  http://{}:{}", hostname_str, port);
        }
    }
    println!("  http://127.0.0.1:{}", port);
    println!("\n按 CTRL+C 停止。");
    let url = format!("http://127.0.0.1:{}", port);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if webbrowser::open(&url).is_err() {
            warn!("无法自动打开浏览器");
        }
    });
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .context("Web 服务器运行失败")?;
    Ok(())
}

async fn serve_index() -> impl IntoResponse {
    match Asset::get("index.html") {
        Some(content) => Html(content.data).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "错误: index.html 未嵌入。",
        )
            .into_response(),
    }
}

type AppState = Arc<Mutex<ConfigManager>>;

#[derive(Deserialize)]
struct SaveServerPayload {
    name: String,
    original_name: Option<String>,
    #[serde(flatten)]
    server: Server,
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
}

async fn get_servers(State(state): State<AppState>) -> Response {
    let guard = match state.lock() {
        Ok(guard) => guard,
        Err(p) => {
            log::error!("Mutex poisoned: {}", p);
            return (StatusCode::INTERNAL_SERVER_ERROR, "服务器内部状态错误").into_response();
        }
    };
    match guard.read() {
        Ok(config) => {
            let api_servers: BTreeMap<String, Server> = config
                .servers
                .into_iter()
                .map(|(name, mut server)| {
                    if let Some(encrypted) = server.password_encrypted.take() {
                        server.password = Some(crypto::decrypt_password(&encrypted));
                        server.is_password_encrypted = Some(true);
                    } else if server.password.is_some() {
                        server.is_password_encrypted = Some(false);
                    }
                    (name, server)
                })
                .collect();
            Json(api_servers).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn save_server(
    State(state): State<AppState>,
    Json(payload): Json<SaveServerPayload>,
) -> Response {
    let guard = match state.lock() {
        Ok(guard) => guard,
        Err(p) => {
            log::error!("Mutex poisoned: {}", p);
            return (StatusCode::INTERNAL_SERVER_ERROR, "服务器内部状态错误").into_response();
        }
    };
    let mut config = match guard.read() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut server_to_save = payload.server;
    server_to_save.keyfile = server_to_save.keyfile.filter(|s| !s.is_empty());
    server_to_save.ssh_prefix_command = server_to_save.ssh_prefix_command.filter(|s| !s.is_empty());
    server_to_save.port_forwards.retain(|pf| match pf {
        PortForward::Local {
            local_port,
            remote_host,
            remote_port,
        } => local_port.is_some() && !remote_host.is_empty() && remote_port.is_some(),
        PortForward::Remote {
            remote_port,
            local_host,
            local_port,
        } => remote_port.is_some() && !local_host.is_empty() && local_port.is_some(),
        PortForward::Dynamic { local_port } => local_port.is_some(),
    });
    let store_plaintext = server_to_save.store_password_as_plaintext.unwrap_or(false);
    let password_from_frontend = server_to_save.password.take();
    server_to_save.password_encrypted = None;
    if let Some(pass) = password_from_frontend.filter(|s| !s.is_empty()) {
        if store_plaintext {
            server_to_save.password = Some(pass);
        } else {
            match crypto::encrypt_password(&pass) {
                Ok(encrypted) => server_to_save.password_encrypted = Some(encrypted),
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            }
        }
    }
    server_to_save.store_password_as_plaintext = None;
    server_to_save.is_password_encrypted = None;
    if let Some(original_name) = payload.original_name.as_deref() {
        if original_name != payload.name {
            config.servers.remove(original_name);
        }
    }
    config.servers.insert(payload.name, server_to_save);
    match guard.write(&config) {
        Ok(_) => Json(StatusResponse { status: "ok" }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn delete_server(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let guard = match state.lock() {
        Ok(guard) => guard,
        Err(p) => {
            log::error!("Mutex poisoned: {}", p);
            return (StatusCode::INTERNAL_SERVER_ERROR, "服务器内部状态错误").into_response();
        }
    };
    let mut config = match guard.read() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if config.servers.remove(&name).is_some() {
        match guard.write(&config) {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        (StatusCode::NOT_FOUND, format!("未找到服务器: {}", name)).into_response()
    }
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
        Some(Commands::Web) => run_web_ui().await?,
        Some(Commands::Config(cmd)) => config_cli::handle_config_command(cmd, &config_manager)?,
        Some(Commands::Api(cmd)) => api::handle_api_command(cmd, &config_manager)?,
        Some(Commands::Export) => transfer::export_config(&config_manager)?,
        Some(Commands::Import { data, force }) => {
            transfer::import_config(&config_manager, &data, force)?
        }
        Some(Commands::Tutorial) => tutorial::show()?,
    }

    Ok(())
}
