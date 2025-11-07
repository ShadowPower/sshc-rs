use crate::{crypto, ConfigManager, Server};
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    /// 以 JSON 数组格式列出所有服务器名称
    List,
    /// 以 JSON 对象格式获取指定服务器的配置（密码为明文）
    Get {
        /// 服务器名称
        name: String,
    },
    /// 从 stdin 添加或更新服务器配置 (JSON)（密码为明文）
    Set,
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

pub fn handle_api_command(cmd: ApiCommands, manager: &ConfigManager) -> Result<()> {
    match cmd {
        ApiCommands::List => {
            let config = manager.read()?;
            let names: Vec<&String> = config.servers.keys().collect();
            println!("{}", serde_json::to_string(&names)?);
        }
        ApiCommands::Get { name } => {
            let config = manager.read()?;
            let server = config
                .servers
                .get(&name)
                .ok_or_else(|| anyhow!("未找到服务器: {}", name))?;

            let mut server_for_api = server.clone();

            // 解密密码（如果存在），并将其放入 'password' 字段
            if let Some(encrypted_pass) = server_for_api.password_encrypted.take() {
                server_for_api.password = Some(crypto::decrypt_password(&encrypted_pass));
            }
            // 清理掉不应在 API 输出中出现的临时字段
            server_for_api.store_password_as_plaintext = None;
            server_for_api.is_password_encrypted = None;

            println!("{}", serde_json::to_string_pretty(&server_for_api)?);
        }
        ApiCommands::Set => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            let payload: SetPayload =
                serde_json::from_str(&buffer).context("解析 STDIN 的 JSON 数据失败")?;

            let mut config = manager.read()?;
            let mut server_to_save = payload.server;

            // 如果 API 传入了明文密码，则对其进行加密以进行存储
            if let Some(plaintext_pass) = server_to_save.password.take() {
                if !plaintext_pass.is_empty() {
                    let encrypted = crypto::encrypt_password(&plaintext_pass)?;
                    server_to_save.password_encrypted = Some(encrypted);
                } else {
                    // 传入空密码字符串表示移除密码
                    server_to_save.password_encrypted = None;
                }
            }
            // 确保不会将明文密码写入配置文件
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
