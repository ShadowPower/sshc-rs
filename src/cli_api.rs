use crate::{
    config::{ConfigManager, Server},
    crypto,
};
use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    io::{self, Read},
};

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    /// 以 JSON 数组格式列出所有服务器名称
    List,
    /// 以 JSON 对象格式获取指定服务器的配置（不包含密码）。省略名称则获取所有服务器。
    Get {
        /// 服务器名称 (可选)
        name: Option<String>,
    },
    /// 从 stdin 或参数添加或更新服务器配置 (JSON)
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
    server: Map<String, Value>,
}

fn server_to_api(mut server: Server) -> Server {
    server.password = None;
    server.password_encrypted = None;
    server.store_password_as_plaintext = None;
    server.is_password_encrypted = None;
    server
}

fn prepare_server_for_save(
    mut server_to_save: Server,
    existing_server: Option<&Server>,
    password_was_provided: bool,
) -> Result<Server> {
    if password_was_provided {
        match server_to_save.password.take().filter(|s| !s.is_empty()) {
            Some(plaintext_pass) => {
                let encrypted = crypto::encrypt_password(&plaintext_pass)?;
                server_to_save.password = None;
                server_to_save.password_encrypted = Some(encrypted);
            }
            None => {
                server_to_save.password = None;
                server_to_save.password_encrypted = None;
            }
        }
    } else if let Some(existing_server) = existing_server {
        server_to_save.password = existing_server.password.clone();
        server_to_save.password_encrypted = existing_server.password_encrypted.clone();
    } else {
        server_to_save.password = None;
        server_to_save.password_encrypted = None;
    }

    server_to_save.store_password_as_plaintext = None;
    server_to_save.is_password_encrypted = None;
    Ok(server_to_save)
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
            let password_was_provided = payload.server.contains_key("password");
            let server_to_save: Server = serde_json::from_value(Value::Object(payload.server))
                .context("解析 server 字段失败")?;

            let mut config = manager.read()?;
            let existing_server = config.servers.get(&payload.name);
            let server_to_save =
                prepare_server_for_save(server_to_save, existing_server, password_was_provided)?;

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

#[cfg(test)]
mod tests {
    use super::{prepare_server_for_save, server_to_api};
    use crate::{config::Server, crypto};

    fn sample_server() -> Server {
        Server {
            host: "example.com".to_string(),
            user: "tester".to_string(),
            ..Server::default()
        }
    }

    #[test]
    fn api_export_omits_password_fields() {
        let mut server = sample_server();
        server.password = Some("plain-secret".to_string());
        server.password_encrypted = Some("encrypted-secret".to_string());
        server.store_password_as_plaintext = Some(true);
        server.is_password_encrypted = Some(false);

        let api_server = server_to_api(server);
        let json = serde_json::to_value(api_server).expect("serialize server");

        assert!(json.get("password").is_none());
        assert!(json.get("password_encrypted").is_none());
        assert!(json.get("store_password_as_plaintext").is_none());
        assert!(json.get("is_password_encrypted").is_none());
    }

    #[test]
    fn api_import_keeps_existing_password_when_password_is_omitted() {
        let mut incoming_server = sample_server();
        incoming_server.host = "new.example.com".to_string();

        let mut existing_server = sample_server();
        existing_server.password = Some("plain-secret".to_string());

        let saved_server = prepare_server_for_save(incoming_server, Some(&existing_server), false)
            .expect("prepare server");

        assert_eq!(saved_server.password.as_deref(), Some("plain-secret"));
        assert!(saved_server.password_encrypted.is_none());
    }

    #[test]
    fn api_import_encrypts_new_password_when_password_is_provided() {
        let mut incoming_server = sample_server();
        incoming_server.password = Some("new-secret".to_string());

        let saved_server =
            prepare_server_for_save(incoming_server, None, true).expect("prepare server");

        assert!(saved_server.password.is_none());
        assert_eq!(
            saved_server
                .password_encrypted
                .as_deref()
                .map(crypto::decrypt_password)
                .as_deref(),
            Some("new-secret")
        );
    }

    #[test]
    fn api_import_clears_password_when_empty_password_is_provided() {
        let mut incoming_server = sample_server();
        incoming_server.password = Some(String::new());

        let mut existing_server = sample_server();
        existing_server.password_encrypted = Some("existing-secret".to_string());

        let saved_server = prepare_server_for_save(incoming_server, Some(&existing_server), true)
            .expect("prepare server");

        assert!(saved_server.password.is_none());
        assert!(saved_server.password_encrypted.is_none());
    }
}
