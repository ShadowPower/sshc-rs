use crate::{
    config::{ConfigManager, Server},
    crypto,
};
use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{self, Read},
};

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    /// 以 JSON 数组格式列出所有服务器名称
    List,
    /// 以 JSON 对象格式获取指定服务器的配置（密码为明文）。省略名称则获取所有服务器。
    Get {
        /// 服务器名称 (可选)
        name: Option<String>,
    },
    /// 从 stdin 或参数添加或更新服务器配置 (JSON)（密码为明文）
    Set {
        /// 包含服务器配置的 JSON 字符串
        #[arg(short, long)]
        data: Option<String>,
    },
    /// 删除一个服务器
    #[command(alias = "rm")]
    Remove {
        /// 服务器名称
        name: String,
    },
}

#[derive(Deserialize)]
struct SetPayload {
    name: String,
    server: Server,
}

fn server_to_api(mut server: Server) -> Server {
    if let Some(encrypted_pass) = server.password_encrypted.take() {
        server.password = Some(crypto::decrypt_password(&encrypted_pass));
    }
    server.store_password_as_plaintext = None;
    server.is_password_encrypted = None;
    server
}

pub fn handle_api_command(cmd: ApiCommands, manager: &ConfigManager) -> Result<()> {
    match cmd {
        ApiCommands::List => {
            let config = manager.read()?;
            let names: Vec<&String> = config.servers.keys().collect();
            println!("{}", serde_json::to_string(&names)?);
        }
        ApiCommands::Get { name } => match name {
            Some(name) => {
                let config = manager.read()?;
                let server = config
                    .servers
                    .get(&name)
                    .ok_or_else(|| anyhow!("未找到服务器: {}", name))?
                    .clone();

                println!("{}", serde_json::to_string_pretty(&server_to_api(server))?);
            }
            None => {
                let config = manager.read()?;
                let all_servers: BTreeMap<String, Server> = config
                    .servers
                    .into_iter()
                    .map(|(name, server)| (name, server_to_api(server)))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&all_servers)?);
            }
        },
        ApiCommands::Set { data } => {
            let buffer = match data {
                Some(d) => d,
                None => {
                    let mut stdin_buffer = String::new();
                    io::stdin().read_to_string(&mut stdin_buffer)?;
                    stdin_buffer
                }
            };

            let payload: SetPayload =
                serde_json::from_str(&buffer).context("解析 JSON 数据失败")?;

            let mut config = manager.read()?;
            let mut server_to_save = payload.server;

            if let Some(plaintext_pass) = server_to_save.password.take() {
                if !plaintext_pass.is_empty() {
                    let encrypted = crypto::encrypt_password(&plaintext_pass)?;
                    server_to_save.password_encrypted = Some(encrypted);
                } else {
                    server_to_save.password_encrypted = None;
                }
            }
            server_to_save.password = None;
            server_to_save.store_password_as_plaintext = None;
            server_to_save.is_password_encrypted = None;

            config.servers.insert(payload.name, server_to_save);
            manager.write(&config)?;
        }
        ApiCommands::Remove { name } => {
            let mut config = manager.read()?;
            if config.servers.remove(&name).is_none() {
                return Err(anyhow!("未找到要删除的服务器: {}", name));
            }
            manager.write(&config)?;
        }
    }
    Ok(())
}
