use crate::config::Server;
use crate::ssh::SshProcessBuilder;
use anyhow::{Context, Result, anyhow};
use base64::engine::general_purpose::STANDARD as B64;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs_extra::dir::get_size;
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

enum RemotePathType {
    File,
    Directory,
    NotFound,
}

#[derive(Debug, Clone, Copy)]
enum CompressionAlgorithm {
    Gzip,
    Zstd,
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

fn execute_remote_command_for_string(server: &Server, command: &str) -> Result<String> {
    let output = SshProcessBuilder::new(server, command).execute_for_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "远程命令执行失败: {}\n命令: {}",
            stderr.trim(),
            command
        ));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn get_remote_path_type(server: &Server, remote_path: &str) -> Result<RemotePathType> {
    let quoted_path = quote_remote_path(remote_path);
    let command = format!(
        "if [ -d {} ]; then echo dir; elif [ -f {} ]; then echo file; else echo not_found; fi",
        quoted_path, quoted_path
    );
    let output = execute_remote_command_for_string(server, &command)?;
    match output.as_str() {
        "file" => Ok(RemotePathType::File),
        "dir" => Ok(RemotePathType::Directory),
        _ => Ok(RemotePathType::NotFound),
    }
}

fn get_remote_size(server: &Server, remote_path: &str, path_type: &RemotePathType) -> Result<u64> {
    let quoted_path = quote_remote_path(remote_path);
    let command = match path_type {
        RemotePathType::File => format!("stat -c%s {}", quoted_path),
        RemotePathType::Directory => format!("du -sb {} | cut -f1", quoted_path),
        RemotePathType::NotFound => return Err(anyhow!("远程路径未找到: {}", remote_path)),
    };
    let output = execute_remote_command_for_string(server, &command)?;
    output.parse::<u64>().context("解析远程文件大小时失败")
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

fn detect_compression_algorithm(server: &Server) -> Result<CompressionAlgorithm> {
    let command = "command -v zstd >/dev/null 2>&1";
    let output = SshProcessBuilder::new(server, command).execute_for_output();

    match output {
        Ok(out) if out.status.success() => {
            log::info!("服务器支持 zstd，将优先使用 zstd 进行压缩");
            Ok(CompressionAlgorithm::Zstd)
        }
        _ => {
            log::info!("服务器不支持 zstd，将回退到 gzip 进行压缩");
            Ok(CompressionAlgorithm::Gzip)
        }
    }
}

pub fn upload(server: &Server, local_path: &Path, destination: &str) -> Result<()> {
    if !local_path.exists() {
        return Err(anyhow!("本地路径不存在: {:?}", local_path));
    }

    let algorithm = detect_compression_algorithm(server)?;

    let local_base_name = local_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("无法获取本地文件名: {:?}", local_path))?;

    let is_dir_upload = local_path.is_dir();

    // 根据用户输入决定最终的远程路径
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
    let decompressor_cmd = match algorithm {
        CompressionAlgorithm::Gzip => "gzip -d",
        CompressionAlgorithm::Zstd => "zstd -d -",
    };

    let remote_command = if is_dir_upload {
        format!(
            "mkdir -p {} && cd {} && base64 -d | {} | tar -xf -",
            quoted_final_path, quoted_final_path, decompressor_cmd
        )
    } else {
        format!(
            "mkdir -p \"$(dirname {})\" && base64 -d | {} > {}",
            quoted_final_path, decompressor_cmd, quoted_final_path
        )
    };

    let total_size = if is_dir_upload {
        get_size(local_path).context("计算目录大小时失败")?
    } else {
        fs::metadata(local_path)?.len()
    };

    let pb = create_progress_bar(total_size, "上传中");
    let mut child = SshProcessBuilder::new(server, &remote_command).spawn_for_io()?;

    let ssh_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdin"))?;
    let mut b64_writer = base64::write::EncoderWriter::new(ssh_stdin, &B64);

    match algorithm {
        CompressionAlgorithm::Gzip => {
            let mut gz_writer = GzEncoder::new(&mut b64_writer, Compression::fast());
            if is_dir_upload {
                let mut tar_builder = tar::Builder::new(&mut gz_writer);
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
            let mut zstd_writer = zstd::stream::Encoder::new(&mut b64_writer, 1)?;
            if is_dir_upload {
                let mut tar_builder = tar::Builder::new(&mut zstd_writer);
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

    b64_writer.finish()?;

    let output = child.wait_with_output()?;
    pb.finish_with_message("上传完成");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("上传失败: {}", stderr.trim()));
    }
    Ok(())
}

pub fn download(server: &Server, remote_path_str: &str, local_path: &Path) -> Result<()> {
    let path_type = get_remote_path_type(server, remote_path_str)?;
    let total_size = get_remote_size(server, remote_path_str, &path_type)?;
    let algorithm = detect_compression_algorithm(server)?;

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

    let pb = create_progress_bar(total_size, "下载中");

    let quoted_remote_path = quote_remote_path(remote_path_str);
    let compressor_cmd = match algorithm {
        CompressionAlgorithm::Gzip => "gzip -1 -c",
        CompressionAlgorithm::Zstd => "zstd -1 -c",
    };

    let remote_command = match path_type {
        RemotePathType::File => {
            format!("{} {} | base64 -w 0", compressor_cmd, quoted_remote_path)
        }
        RemotePathType::Directory => {
            format!(
                "tar -cf - -C {} . | {} | base64 -w 0",
                quoted_remote_path, compressor_cmd
            )
        }
        RemotePathType::NotFound => return Err(anyhow!("远程路径未找到: {}", remote_path_str)),
    };

    let mut child = SshProcessBuilder::new(server, &remote_command).spawn_for_io()?;

    let ssh_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdout"))?;
    let b64_reader = base64::read::DecoderReader::new(ssh_stdout, &B64);

    let decompressor: Box<dyn io::Read> = match algorithm {
        CompressionAlgorithm::Gzip => Box::new(GzDecoder::new(b64_reader)),
        CompressionAlgorithm::Zstd => Box::new(zstd::stream::Decoder::new(b64_reader)?),
    };

    let mut progress_reader = pb.wrap_read(decompressor);

    match path_type {
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
        return Err(anyhow!("下载失败: {}", stderr.trim()));
    }
    Ok(())
}
