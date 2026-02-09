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

        let group_tag = match &self.server.group {
            Some(g) if !g.is_empty() => format!("[{}] ", g),
            _ => String::new(),
        };

        let connection_info = if self.server.user.is_empty() || self.server.host.is_empty() {
            "配置不完整".to_string()
        } else {
            format!("{}@{}", self.server.user, self.server.host)
        };
        write!(
            f,
            "{}{} ({}) - {}",
            group_tag, display_name, self.name, connection_info
        )
    }
}

pub fn interactive_connect(config_manager: &ConfigManager, mode: ConnectMode) -> Result<()> {
    let config = config_manager.read()?;
    if config.servers.is_empty() {
        println!("未配置服务器。请使用 'sshc web' 或 'sshc config add' 添加。");
        return Ok(());
    }

    // 排序逻辑：先按分组顺序，再按名称
    let mut options: Vec<ServerSelectItem> = config
        .servers
        .iter()
        .map(|(name, server)| ServerSelectItem { name, server })
        .collect();

    options.sort_by(|a, b| {
        let group_idx_a = a
            .server
            .group
            .as_ref()
            .and_then(|g| config.groups.iter().position(|x| x == g))
            .unwrap_or(usize::MAX);
        let group_idx_b = b
            .server
            .group
            .as_ref()
            .and_then(|g| config.groups.iter().position(|x| x == g))
            .unwrap_or(usize::MAX);

        if group_idx_a != group_idx_b {
            return group_idx_a.cmp(&group_idx_b);
        }

        // 如果分组相同（或都未分组），按显示名称排序
        let name_a = a.server.display_name.as_deref().unwrap_or(a.name);
        let name_b = b.server.display_name.as_deref().unwrap_or(b.name);
        name_a.cmp(name_b)
    });

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
