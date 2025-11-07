use crate::{ConfigManager, filezilla, ssh};
use anyhow::Result;
use inquire::Select;
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum ConnectMode {
    Ssh,
    Filezilla,
}

struct ServerSelectItem<'a> {
    name: &'a str,
    server: &'a crate::config::Server,
}

impl<'a> fmt::Display for ServerSelectItem<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = self
            .server
            .display_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(self.name);
        let connection_info = format!("{}@{}", self.server.user, self.server.host);
        write!(f, "{} ({}) - {}", display_name, self.name, connection_info)
    }
}

pub fn interactive_connect(config_manager: &ConfigManager, mode: ConnectMode) -> Result<()> {
    let config = config_manager.read()?;
    if config.servers.is_empty() {
        println!("未配置服务器。请使用 'sshc web' 或 'sshc config add' 添加。");
        return Ok(());
    }

    let options: Vec<ServerSelectItem> = config
        .servers
        .iter()
        .map(|(name, server)| ServerSelectItem { name, server })
        .collect();

    let terminal_height = crossterm::terminal::size()
        .map(|(_, height)| height - 2)
        .unwrap_or(15);
    let page_size = (terminal_height as usize).saturating_sub(4).max(5);

    let selected = Select::new("请选择一个服务器进行连接:", options)
        .with_help_message("输入以筛选，回车键确认，ESC 取消")
        .with_page_size(page_size)
        .prompt_skippable()?;

    if let Some(choice) = selected {
        let server = choice.server;
        match mode {
            ConnectMode::Ssh => ssh::connect(server)?,
            ConnectMode::Filezilla => filezilla::connect(server)?,
        }
    }

    Ok(())
}
