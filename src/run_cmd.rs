use crate::{ConfigManager, config::Server, ssh::SshProcessBuilder};
use anyhow::{Result, anyhow};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct RunOutcome {
    server_name: String,
    duration: Duration,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    spawn_error: Option<String>,
}

pub fn run(manager: &ConfigManager, target: &str, command: &str, parallel: bool) -> Result<()> {
    let command = command.trim();
    if command.is_empty() {
        return Err(anyhow!("远程命令不能为空"));
    }

    let config = manager.read()?;
    if config.servers.is_empty() {
        return Err(anyhow!("未配置服务器"));
    }

    let targets = resolve_targets(&config.servers, target)?;
    if targets.is_empty() {
        return Err(anyhow!("没有匹配到任何服务器"));
    }

    println!(
        "将在 {} 台服务器上执行命令: {}",
        targets.len(),
        command.replace('\n', " ")
    );
    println!("执行模式: {}", if parallel { "并行" } else { "串行" });

    let outcomes = if parallel {
        let mut handles = Vec::with_capacity(targets.len());
        for (server_name, server) in targets {
            let cmd = command.to_string();
            handles.push(std::thread::spawn(move || {
                exec_one(server_name, server, &cmd)
            }));
        }

        let mut outcomes = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(outcome) => outcomes.push(outcome),
                Err(_) => outcomes.push(RunOutcome {
                    server_name: "<thread panic>".to_string(),
                    duration: Duration::from_secs(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: None,
                    spawn_error: Some("执行线程异常退出".to_string()),
                }),
            }
        }
        outcomes
    } else {
        targets
            .into_iter()
            .map(|(server_name, server)| exec_one(server_name, server, command))
            .collect()
    };

    let mut ok_count = 0usize;
    let mut fail_count = 0usize;
    for outcome in &outcomes {
        let elapsed_ms = outcome.duration.as_millis();
        println!();
        println!("===== {} =====", outcome.server_name);
        match (&outcome.spawn_error, outcome.exit_code) {
            (Some(err), _) => {
                println!("[ERR] 启动失败 ({} ms): {}", elapsed_ms, err);
                fail_count += 1;
            }
            (None, Some(0)) => {
                println!("[OK]  执行成功 ({} ms)", elapsed_ms);
                ok_count += 1;
            }
            (None, code) => {
                println!("[ERR] 执行失败 ({} ms), exit={:?}", elapsed_ms, code);
                fail_count += 1;
            }
        }

        if !outcome.stdout.trim().is_empty() {
            println!("--- stdout ---");
            println!("{}", outcome.stdout.trim_end());
        }
        if !outcome.stderr.trim().is_empty() {
            println!("--- stderr ---");
            println!("{}", outcome.stderr.trim_end());
        }
    }

    println!();
    println!("执行汇总: {} 成功, {} 失败", ok_count, fail_count);
    if fail_count > 0 {
        return Err(anyhow!("{} 台服务器执行失败", fail_count));
    }
    Ok(())
}

fn resolve_targets(
    servers: &std::collections::BTreeMap<String, Server>,
    target: &str,
) -> Result<Vec<(String, Server)>> {
    let target = target.trim();
    if target == "all" || target == "*" {
        return Ok(servers
            .iter()
            .map(|(name, server)| (name.clone(), server.clone()))
            .collect());
    }

    if let Some(group_name) = target.strip_prefix('@') {
        let list: Vec<(String, Server)> = servers
            .iter()
            .filter(|(_, server)| server.group.as_deref() == Some(group_name))
            .map(|(name, server)| (name.clone(), server.clone()))
            .collect();
        if list.is_empty() {
            return Err(anyhow!("分组 '{}' 下没有服务器", group_name));
        }
        return Ok(list);
    }

    if let Some(server) = servers.get(target) {
        return Ok(vec![(target.to_string(), server.clone())]);
    }

    let fuzzy: Vec<(String, Server)> = servers
        .iter()
        .filter(|(name, server)| {
            name.contains(target)
                || server
                    .display_name
                    .as_deref()
                    .is_some_and(|display_name| display_name.contains(target))
        })
        .map(|(name, server)| (name.clone(), server.clone()))
        .collect();
    if fuzzy.is_empty() {
        return Err(anyhow!("未找到目标 '{}'", target));
    }
    Ok(fuzzy)
}

fn exec_one(server_name: String, server: Server, command: &str) -> RunOutcome {
    let start = Instant::now();

    if server.host.trim().is_empty() || server.user.trim().is_empty() {
        return RunOutcome {
            server_name,
            duration: start.elapsed(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            spawn_error: Some("配置不完整（缺少 host 或 user）".to_string()),
        };
    }

    let child = match SshProcessBuilder::new(&server, command).spawn_for_io() {
        Ok(c) => c,
        Err(e) => {
            return RunOutcome {
                server_name,
                duration: start.elapsed(),
                stdout: String::new(),
                stderr: String::new(),
                exit_code: None,
                spawn_error: Some(e.to_string()),
            };
        }
    };

    match child.wait_with_output() {
        Ok(output) => RunOutcome {
            server_name,
            duration: start.elapsed(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code(),
            spawn_error: None,
        },
        Err(e) => RunOutcome {
            server_name,
            duration: start.elapsed(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            spawn_error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_targets;
    use crate::config::Server;
    use std::collections::BTreeMap;

    fn sample_servers() -> BTreeMap<String, Server> {
        let mut map = BTreeMap::new();
        map.insert(
            "prod-api".to_string(),
            Server {
                group: Some("backend".to_string()),
                display_name: Some("生产 API".to_string()),
                host: "10.0.0.1".to_string(),
                user: "root".to_string(),
                ..Default::default()
            },
        );
        map.insert(
            "prod-web".to_string(),
            Server {
                group: Some("frontend".to_string()),
                display_name: Some("生产 Web".to_string()),
                host: "10.0.0.2".to_string(),
                user: "root".to_string(),
                ..Default::default()
            },
        );
        map
    }

    #[test]
    fn resolve_target_all() {
        let servers = sample_servers();
        let result = resolve_targets(&servers, "all").expect("resolve all");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn resolve_target_group() {
        let servers = sample_servers();
        let result = resolve_targets(&servers, "@backend").expect("resolve group");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "prod-api");
    }

    #[test]
    fn resolve_target_exact() {
        let servers = sample_servers();
        let result = resolve_targets(&servers, "prod-web").expect("resolve exact");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "prod-web");
    }

    #[test]
    fn resolve_target_fuzzy() {
        let servers = sample_servers();
        let result = resolve_targets(&servers, "生产").expect("resolve fuzzy");
        assert_eq!(result.len(), 2);
    }
}
