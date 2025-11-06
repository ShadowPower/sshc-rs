use crate::{ConfigManager, Server};
use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    /// 以 JSON 数组格式列出所有服务器名称
    List,
    /// 以 JSON 对象格式获取指定服务器的配置
    Get {
        /// 服务器名称
        name: String,
    },
    /// 从 stdin 添加或更新服务器配置 (JSON)
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
    #[serde(flatten)]
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
            println!("{}", serde_json::to_string_pretty(server)?);
        }
        ApiCommands::Set => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            let payload: SetPayload =
                serde_json::from_str(&buffer).context("解析 STDIN 的 JSON 数据失败")?;

            let mut config = manager.read()?;
            config.servers.insert(payload.name, payload.server);
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
