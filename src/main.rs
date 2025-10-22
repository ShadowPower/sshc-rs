use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use clap::{CommandFactory, Parser};
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

// --- 静态文件嵌入 ---
#[derive(Embed)]
#[folder = "."]
#[include = "index.html"]
struct Asset;

// --- 命令行接口定义 (CLI) ---
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "一个简单的 SSH 连接管理器。",
    after_help = "示例: 'sshc my-server' (SSH), 'sshc my-server -f' (FileZilla), 'sshc --config' (Web UI)"
)]
struct Cli {
    #[arg(help = "要连接的服务器名称。")]
    server_name: Option<String>,
    #[arg(long, help = "打开基于 Web 的配置界面。")]
    config: bool,
    #[arg(short, long, help = "列出所有已配置的服务器。")]
    list: bool,
    #[arg(short, long, help = "使用 FileZilla 代替 SSH 连接指定的服务器。")]
    filezilla: bool,
}

// --- 配置数据结构 ---
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Config {
    #[serde(default)]
    servers: BTreeMap<String, Server>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
struct Server {
    host: String,
    user: String,
    display_name: Option<String>,
    port: Option<u16>,
    keyfile: Option<String>,
    x11_forwarding: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    store_password_as_plaintext: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_encrypted: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    port_forwards: Vec<PortForward>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum PortForward {
    Local {
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    },
    Remote {
        remote_port: u16,
        local_host: String,
        local_port: u16,
    },
    Dynamic {
        local_port: u16,
    },
}

// --- 配置管理器 ---
struct ConfigManager {
    path: PathBuf,
}

impl ConfigManager {
    fn new() -> Result<Self> {
        let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("无法获取用户主目录"))?;
        let config_dir = home_dir.join(".sshc");
        Ok(Self {
            path: config_dir.join("config.toml"),
        })
    }

    fn ensure_exists(&self) -> Result<()> {
        let dir = self.path.parent().unwrap();
        fs::create_dir_all(dir).with_context(|| format!("无法创建配置目录: {:?}", dir))?;
        if !self.path.exists() {
            let default_config = Config::default();
            fs::write(&self.path, toml::to_string(&default_config)?)
                .with_context(|| format!("无法创建默认配置文件: {:?}", self.path))?;
        }
        Ok(())
    }

    fn read(&self) -> Result<Config> {
        self.ensure_exists()?;
        let content = fs::read_to_string(&self.path)?;
        toml::from_str(&content).with_context(|| "解析 TOML 配置文件失败")
    }

    fn write(&self, config: &Config) -> Result<()> {
        self.ensure_exists()?;
        fs::write(&self.path, toml::to_string_pretty(config)?)
            .with_context(|| format!("无法写入配置文件: {:?}", self.path))
    }

    fn get_servers_for_api(&self) -> Result<BTreeMap<String, Server>> {
        let mut config = self.read()?;
        for server in config.servers.values_mut() {
            if let Some(encrypted) = server.password_encrypted.take() {
                server.password = Some(crypto::decrypt_password(&encrypted));
            }
        }
        Ok(config.servers)
    }

    fn save_server(
        &self,
        name: &str,
        mut server_data: Server,
        original_name: Option<&str>,
    ) -> Result<()> {
        let mut config = self.read()?;
        if let Some(orig_name) = original_name {
            if orig_name != name {
                config.servers.remove(orig_name);
            }
        }
        let store_plaintext = server_data.store_password_as_plaintext.unwrap_or(false);
        if let Some(pass) = server_data.password.take().filter(|s| !s.is_empty()) {
            if store_plaintext {
                server_data.password = Some(pass);
                server_data.password_encrypted = None;
            } else {
                server_data.password_encrypted = Some(crypto::encrypt_password(&pass)?);
                server_data.password = None;
            }
        }
        server_data.store_password_as_plaintext = None;
        config.servers.insert(name.to_string(), server_data);
        self.write(&config)
    }

    fn delete_server(&self, name: &str) -> Result<bool> {
        let mut config = self.read()?;
        if config.servers.remove(name).is_some() {
            self.write(&config)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// --- 加密模块 ---
mod crypto {
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
mod ssh {
    use super::{PortForward, Server, crypto};
    use anyhow::{Context, Result};
    #[cfg(not(windows))]
    use anyhow::anyhow;
    use log::info;
    use std::process::Command;

    pub fn connect(server: &Server) -> Result<()> {
        let mut cmd = Command::new("ssh");
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
                    local_port,
                    remote_host,
                    remote_port,
                } => {
                    cmd.arg("-L")
                        .arg(format!("{}:{}:{}", local_port, remote_host, remote_port));
                }
                PortForward::Remote {
                    remote_port,
                    local_host,
                    local_port,
                } => {
                    cmd.arg("-R")
                        .arg(format!("{}:{}:{}", remote_port, local_host, local_port));
                }
                PortForward::Dynamic { local_port } => {
                    cmd.arg("-D").arg(local_port.to_string());
                }
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
            info!("正在建立 SSH 连接 (密码认证)...");

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
            info!("正在建立 SSH 连接 (密钥认证)...");
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
mod filezilla {
    use super::{Server, crypto};
    use anyhow::{Context, Result, anyhow};
    use log::{info, warn};
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
        info!("启动 FileZilla 连接到 {}@{}...", server.user, server.host);
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
    server: Server,
    original_name: Option<String>,
}

async fn get_servers(State(state): State<AppState>) -> Response {
    match state.lock().unwrap().get_servers_for_api() {
        Ok(servers) => Json(servers).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn save_server(
    State(state): State<AppState>,
    Json(payload): Json<SaveServerPayload>,
) -> Response {
    match state.lock().unwrap().save_server(
        &payload.name,
        payload.server,
        payload.original_name.as_deref(),
    ) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn delete_server(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.lock().unwrap().delete_server(&name) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, format!("未找到服务器: {}", name)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// --- 主程序入口 ---
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Cli::parse();
    let config_manager = ConfigManager::new()?;

    if args.config {
        run_web_ui().await?;
    } else if args.list {
        let config = config_manager.read()?;
        if config.servers.is_empty() {
            println!("未配置服务器。请使用 'sshc --config' 添加。");
        } else {
            println!("可用的服务器:");
            for (name, server) in &config.servers {
                let display = server
                    .display_name
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(name);
                println!("  - {} ({})", display, name);
                println!(
                    "    └─ {}@{}:{}",
                    server.user,
                    server.host,
                    server.port.unwrap_or(22)
                );
            }
        }
    } else if let Some(server_name) = args.server_name {
        let config = config_manager.read()?;
        let server = config
            .servers
            .get(&server_name)
            .ok_or_else(|| anyhow!("错误: 未找到服务器 '{}'", server_name))?;
        if args.filezilla {
            filezilla::connect(server)?;
        } else {
            ssh::connect(server)?;
        }
    } else if args.filezilla {
        return Err(anyhow!(
            "错误: -f/--filezilla 标志必须与服务器名称一起使用。"
        ));
    } else {
        Cli::command().print_help()?;
    }

    Ok(())
}
