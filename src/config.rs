use anyhow::{Context, Result, anyhow};
use serde::{self, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};

// --- Serde 辅助模块 ---
mod serde_helpers {
    use super::*;
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
    /// 分组列表，用于定义分组的显示顺序
    #[serde(default)]
    pub groups: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
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