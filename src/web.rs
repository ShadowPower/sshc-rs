use crate::{
    Asset,
    config::{ConfigManager, PortForward, Server},
    crypto,
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use log::warn;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

fn format_url_host(host: IpAddr) -> String {
    match host {
        IpAddr::V6(v6) => format!("[{}]", v6),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

// --- Web UI 后端 ---
pub async fn run_web_ui(bind: IpAddr, port: Option<u16>, no_browser: bool) -> Result<()> {
    let config_manager = Arc::new(Mutex::new(ConfigManager::new()?));
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/config", get(get_config))
        .route("/api/server", post(save_server))
        .route("/api/server/{name}", delete(delete_server))
        .route("/api/groups", post(save_groups))
        .with_state(config_manager);
    let port = match port {
        Some(p) => p,
        None => portpicker::pick_unused_port().context("无法找到可用端口")?,
    };
    let addr = SocketAddr::from((bind, port));
    println!("正在启动 Web UI... 请在浏览器中打开以下任一地址:");
    if bind.is_unspecified() {
        if let Ok(hostname) = hostname::get() {
            if let Ok(hostname_str) = hostname.into_string() {
                println!("  http://{}:{}", hostname_str, port);
            }
        }
        println!("  http://127.0.0.1:{}", port);
    } else if bind.is_loopback() {
        println!("  http://127.0.0.1:{}", port);
    } else {
        println!("  http://{}:{}", format_url_host(bind), port);
    }
    println!("\n按 CTRL+C 停止。");
    if !no_browser {
        let url = if bind.is_unspecified() || bind.is_loopback() {
            format!("http://127.0.0.1:{}", port)
        } else {
            format!("http://{}:{}", format_url_host(bind), port)
        };
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if webbrowser::open(&url).is_err() {
                warn!("无法自动打开浏览器");
            }
        });
    }
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

#[derive(Serialize)]
struct ConfigResponse {
    servers: BTreeMap<String, Server>,
    groups: Vec<String>,
}

async fn get_config(State(state): State<AppState>) -> Response {
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
            Json(ConfigResponse {
                servers: api_servers,
                groups: config.groups,
            })
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

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

async fn save_server(
    State(state): State<AppState>,
    Json(payload): Json<SaveServerPayload>,
) -> Response {
    if payload.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "连接名称不能为空").into_response();
    }
    if payload.server.host.trim().is_empty() || payload.server.user.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "主机和用户名为必填项").into_response();
    }
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
    server_to_save.group = server_to_save.group.filter(|s| !s.is_empty());

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

#[derive(Deserialize)]
struct SaveGroupsPayload {
    groups: Vec<String>,
}

async fn save_groups(
    State(state): State<AppState>,
    Json(payload): Json<SaveGroupsPayload>,
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

    // 我们只更新 groups 列表。重命名分组实际上需要在前端处理好服务器的关联更新，然后调用 server update 或
    // 更好的方式：这里只负责保存顺序/增删。
    // 如果是重命名，前端应该调用 /api/server 批量更新受影响的服务器，或者我们在后端增加专门的重命名接口。
    // 为保持简单，假设前端负责数据一致性（或者重命名时，前端会遍历服务器并更新）。
    // 在这里，我们仅仅覆盖 groups 列表。

    config.groups = payload.groups;

    match guard.write(&config) {
        Ok(_) => Json(StatusResponse { status: "ok" }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
