use crate::{Config, ConfigManager};
use anyhow::{Context, Result, anyhow};
use std::io::{self, Write};

pub fn export_config(manager: &ConfigManager) -> Result<()> {
    let config = manager.read()?;
    let toml_string = toml::to_string(&config)?;
    let compressed = zstd::encode_all(toml_string.as_bytes(), 0).context("压缩配置失败")?;
    let encoded = base85::encode(&compressed);

    println!("复制以下命令并在另一台机器上运行以导入配置:");
    println!("\nsshc import '{}'\n", encoded);
    Ok(())
}

pub fn import_config(manager: &ConfigManager, data: &str, force: bool) -> Result<()> {
    let compressed = base85::decode(data).map_err(|e| anyhow!("Base85 解码失败: {:?}", e))?;
    let toml_bytes = zstd::decode_all(&compressed[..]).context("解压配置失败")?;
    let toml_string = String::from_utf8(toml_bytes).context("配置数据不是有效的 UTF-8")?;

    let new_config: Config = toml::from_str(&toml_string).context("解析 TOML 配置失败")?;

    if !force {
        print!("这将覆盖您当前的配置。是否继续？ [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("导入已取消。");
            return Ok(());
        }
    }

    manager.write(&new_config).context("写入新配置失败")?;
    println!("配置导入成功！");
    Ok(())
}
