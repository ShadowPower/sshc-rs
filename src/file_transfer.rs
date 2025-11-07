use crate::config::Server;
use crate::ssh::SshProcessBuilder;
use anyhow::{Context, Result, anyhow};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs_extra::dir::get_size;
use indicatif::{ProgressBar, ProgressStyle};
use log::info;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    time::Duration,
};

// --- 传输协议 ---
//
// ## 下载协议 (服务器 -> 客户端)
// 服务器在一次连接中，先发送一个文本元数据头，然后紧跟着原始的二进制数据流。
//
// 格式:
// TYPE:<file|dir|not_found>
// SIZE:<bytes>
// COMPRESSION:<zstd|gzip>
// ---DATA---
// [原始二进制压缩数据流...]
//
// ## 上传协议 (客户端 -> 服务器)
// 1. 服务器首先探测自身能力，并向客户端发送一行文本，指明期望的压缩算法。
//    COMPRESSION:<zstd|gzip>
// 2. 服务器随后进入等待状态，准备从 stdin 接收数据。
// 3. 客户端读取这一行信息，然后将使用指定算法压缩后的原始二进制数据流写入服务器的 stdin。

#[derive(Debug, Default)]
struct RemoteMeta {
    path_type: RemotePathType,
    size: u64,
    compression: CompressionAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePathType {
    File,
    Directory,
    NotFound,
}

impl Default for RemotePathType {
    fn default() -> Self {
        RemotePathType::NotFound
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionAlgorithm {
    Gzip,
    Zstd,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        CompressionAlgorithm::Gzip
    }
}

/// 安全地为远程路径添加引号以供 shell 执行，并特殊处理家目录（~）的展开。
/// 例如：`~/foo bar` 会变成 `~/'foo bar'`
fn quote_remote_path(path: &str) -> String {
    if path == "~" {
        return "~".to_string();
    }
    if path.starts_with("~/") {
        let rest = &path[2..];
        return format!("~/'{}'", rest.replace('\'', "'\\''"));
    }
    format!("'{}'", path.replace('\'', "'\\''"))
}

fn create_progress_bar(total_size: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

pub fn upload(server: &Server, local_path: &Path, destination: &str) -> Result<()> {
    if !local_path.exists() {
        return Err(anyhow!("本地路径不存在: {:?}", local_path));
    }

    let local_base_name = local_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("无法获取本地文件名: {:?}", local_path))?;

    let is_dir_upload = local_path.is_dir();

    let final_remote_path =
        if destination.is_empty() || destination == "~" || destination.ends_with('/') {
            let base_dir = if destination.is_empty() {
                "~/"
            } else {
                destination
            };
            format!("{}{}", base_dir, local_base_name)
        } else {
            destination.to_string()
        };

    let quoted_final_path = quote_remote_path(&final_remote_path);

    let remote_command = format!(
        r#"
        set -eo pipefail;
        if command -v zstd >/dev/null 2>&1; then
            echo "COMPRESSION:zstd";
            DECOMP_CMD="zstd -d -";
        else
            echo "COMPRESSION:gzip";
            DECOMP_CMD="gzip -d";
        fi;

        if {is_dir_upload}; then
            mkdir -p {path} && cd {path} && $DECOMP_CMD | tar -xf -;
        else
            mkdir -p "$(dirname {path})" && $DECOMP_CMD > {path};
        fi;
        "#,
        is_dir_upload = if is_dir_upload { "true" } else { "false" },
        path = quoted_final_path
    );

    let mut child = SshProcessBuilder::new(server, &remote_command).spawn_for_io()?;

    let ssh_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdout"))?;
    let mut reader = BufReader::new(ssh_stdout);

    let mut line = String::new();
    reader.read_line(&mut line)?;

    let algorithm = match line.trim() {
        "COMPRESSION:zstd" => {
            info!("服务器选择 zstd 压缩算法。");
            CompressionAlgorithm::Zstd
        }
        "COMPRESSION:gzip" => {
            info!("服务器选择 gzip 压缩算法。");
            CompressionAlgorithm::Gzip
        }
        _ => return Err(anyhow!("从服务器收到了无效的压缩协商响应: {}", line.trim())),
    };

    let total_size = if is_dir_upload {
        get_size(local_path).context("计算目录大小时失败")?
    } else {
        fs::metadata(local_path)?.len()
    };

    let pb = create_progress_bar(total_size, "上传中");
    info!("开始数据传输...");

    let ssh_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdin"))?;

    match algorithm {
        CompressionAlgorithm::Gzip => {
            let mut gz_writer = GzEncoder::new(ssh_stdin, Compression::fast());
            if is_dir_upload {
                let mut progress_writer = pb.wrap_write(&mut gz_writer);
                let mut tar_builder = tar::Builder::new(&mut progress_writer);
                tar_builder.append_dir_all(".", local_path)?;
                tar_builder.finish()?;
            } else {
                let mut source_file = File::open(local_path)?;
                let mut progress_reader = pb.wrap_read(&mut source_file);
                io::copy(&mut progress_reader, &mut gz_writer)?;
            }
            gz_writer.finish()?;
        }
        CompressionAlgorithm::Zstd => {
            let mut zstd_writer = zstd::stream::Encoder::new(ssh_stdin, 1)?;
            if is_dir_upload {
                let mut progress_writer = pb.wrap_write(&mut zstd_writer);
                let mut tar_builder = tar::Builder::new(&mut progress_writer);
                tar_builder.append_dir_all(".", local_path)?;
                tar_builder.finish()?;
            } else {
                let mut source_file = File::open(local_path)?;
                let mut progress_reader = pb.wrap_read(&mut source_file);
                io::copy(&mut progress_reader, &mut zstd_writer)?;
            }
            zstd_writer.finish()?;
        }
    }

    let output = child.wait_with_output()?;
    pb.finish_with_message("上传完成");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("上传失败: {}", stderr.trim()));
    }
    Ok(())
}

pub fn download(server: &Server, remote_path_str: &str, local_path: &Path) -> Result<()> {
    let quoted_remote_path = quote_remote_path(remote_path_str);

    let remote_command = format!(
        r#"
        set -eo pipefail;
        path={quoted_path};

        if [ -d "$path" ]; then
            echo "TYPE:dir";
            if uname | grep -q "Linux"; then
                printf "SIZE:%s\n" $(du -sb "$path" | cut -f1);
            else
                kbytes=$(du -sk "$path" | cut -f1);
                printf "SIZE:%s\n" $((kbytes * 1024));
            fi;
            TYPE_CMD="tar -cf - -C {path} .";
        elif [ -f "$path" ]; then
            echo "TYPE:file";
            if uname | grep -q "Linux"; then
                printf "SIZE:%s\n" $(stat -c%s "$path");
            else
                printf "SIZE:%s\n" $(stat -f%z "$path");
            fi;
            TYPE_CMD="cat {path}";
        else
            echo "TYPE:not_found";
            exit 0;
        fi;

        if command -v zstd >/dev/null 2>&1; then
            echo "COMPRESSION:zstd";
            COMP_CMD="zstd -1 -c";
        else
            echo "COMPRESSION:gzip";
            COMP_CMD="gzip -1 -c";
        fi;

        echo "---DATA---";

        exec $TYPE_CMD | $COMP_CMD;
        "#,
        quoted_path = quoted_remote_path,
        path = "$path"
    );

    let mut child = SshProcessBuilder::new(server, &remote_command).spawn_for_io()?;

    let ssh_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdout"))?;

    let mut reader = BufReader::new(ssh_stdout);
    let mut meta = RemoteMeta::default();

    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Err(anyhow!("SSH 连接在传输元数据时意外关闭"));
        }

        let trimmed = line.trim();
        if trimmed == "---DATA---" {
            break;
        }

        if let Some((key, value)) = trimmed.split_once(':') {
            match key {
                "TYPE" => match value {
                    "file" => meta.path_type = RemotePathType::File,
                    "dir" => meta.path_type = RemotePathType::Directory,
                    "not_found" => return Err(anyhow!("远程路径未找到: {}", remote_path_str)),
                    _ => return Err(anyhow!("未知的远程路径类型: {}", value)),
                },
                "SIZE" => meta.size = value.parse().context("解析远程文件大小时失败")?,
                "COMPRESSION" => match value {
                    "zstd" => meta.compression = CompressionAlgorithm::Zstd,
                    "gzip" => meta.compression = CompressionAlgorithm::Gzip,
                    _ => return Err(anyhow!("未知的压缩算法: {}", value)),
                },
                _ => {}
            }
        }
    }

    info!(
        "成功解析远程元数据: 类型={:?}, 大小={}, 压缩={:?}",
        meta.path_type, meta.size, meta.compression
    );

    let remote_base_name = Path::new(remote_path_str)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download");

    let mut final_local_path = PathBuf::from(local_path);
    if final_local_path.is_dir()
        || final_local_path
            .to_string_lossy()
            .ends_with(std::path::MAIN_SEPARATOR)
    {
        final_local_path.push(remote_base_name);
    }

    let pb = create_progress_bar(meta.size, "下载中");
    info!("开始数据传输...");

    let buffer = reader.buffer().to_vec();
    let underlying_stream = reader.into_inner();
    let chained_reader = io::Cursor::new(buffer).chain(underlying_stream);

    let decompressor: Box<dyn Read> = match meta.compression {
        CompressionAlgorithm::Gzip => Box::new(GzDecoder::new(chained_reader)),
        CompressionAlgorithm::Zstd => Box::new(zstd::stream::Decoder::new(chained_reader)?),
    };

    let mut progress_reader = pb.wrap_read(decompressor);

    match meta.path_type {
        RemotePathType::File => {
            if let Some(parent) = final_local_path.parent() {
                fs::create_dir_all(parent).context("创建本地父目录失败")?;
            }
            let mut dest_file = File::create(&final_local_path).context("创建本地文件失败")?;
            io::copy(&mut progress_reader, &mut dest_file)?;
        }
        RemotePathType::Directory => {
            fs::create_dir_all(&final_local_path).context("创建本地目标目录失败")?;
            let mut archive = tar::Archive::new(progress_reader);
            archive
                .unpack(&final_local_path)
                .context("解包 tar 归档失败")?;
        }
        RemotePathType::NotFound => unreachable!(),
    }

    let output = child.wait_with_output()?;
    pb.finish_with_message("下载完成");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            return Err(anyhow!("下载失败: {}", stderr.trim()));
        }
    }
    Ok(())
}
