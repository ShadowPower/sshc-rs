use crate::{
    config::{ConfigManager, PortForward, Server},
    crypto,
    Asset,
};
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State}, http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json,
    Router,
};
use log::warn;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

// --- Web UI 后端 ---
pub async fn run_web_ui() -> Result<()> {
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
