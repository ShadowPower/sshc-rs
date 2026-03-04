use crate::config::Server;
use crate::ssh::SshProcessBuilder;
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs_extra::dir::get_size;
use indicatif::{ProgressBar, ProgressStyle};
use log::info;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::Child,
    time::Duration,
};

// --- 传输协议 ---
//
// ## 下载协议 (服务器 -> 客户端)
// 服务器在一次连接中，先发送一个文本元数据头，然后紧跟着原始的二进制数据流。
//
// 格式:
// TYPE:<file|dir|not_found|access_denied>
// SIZE:<bytes>
// COMPRESSION:<zstd|gzip>
// ERROR:<可选错误信息>
// ---DATA---
// [原始二进制压缩数据流...]
//
// ## 上传协议 (客户端 -> 服务器)
// 1. 服务器先进行目标路径权限预检，并返回压缩协商行：
//    COMPRESSION:<zstd|gzip>
// 2. 客户端收到协商行后，将压缩后的二进制数据写入服务器 stdin。
// 3. 整个预检 + 数据传输都在同一次 SSH 连接里完成。

#[derive(Debug, Default)]
struct RemoteMeta {
    path_type: RemotePathType,
    size: u64,
    compression: CompressionAlgorithm,
    error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePathType {
    File,
    Directory,
    NotFound,
    AccessDenied,
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

/// 安全地为 Unix shell 远程路径添加引号，并特殊处理家目录（~）的展开。
/// 例如：`~/foo bar` 会变成 `~/'foo bar'`。
fn quote_remote_path_for_sh(path: &str) -> String {
    if path == "~" {
        return "~".to_string();
    }
    if path.starts_with("~/") {
        let rest = &path[2..];
        return format!("~/'{}'", rest.replace('\'', "'\\''"));
    }
    format!("'{}'", path.replace('\'', "'\\''"))
}

fn quote_sh_script_for_double_quotes(script: &str) -> String {
    script
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

fn quote_remote_path_for_powershell(path: &str) -> String {
    format!("'{}'", path.replace('\'', "''"))
}

fn encode_script_utf8_base64(script: &str) -> String {
    let bytes = script.as_bytes();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 生成一个跨平台远程命令：优先走 Windows PowerShell；失败后回退到 Unix sh。
/// 这样可以在一次 SSH 会话内兼容 Linux/macOS 与 Windows OpenSSH 服务器。
fn build_dual_shell_command(powershell_script: &str, sh_script: &str) -> String {
    let encoded_ps = encode_script_utf8_base64(powershell_script);
    let quoted_sh = quote_sh_script_for_double_quotes(sh_script);
    let ps_bootstrap = format!(
        "[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_ps}'))).Invoke()",
        encoded_ps = encoded_ps
    );
    format!(
        r#"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{ps_bootstrap}" || sh -lc "{quoted_sh}""#,
        ps_bootstrap = ps_bootstrap,
        quoted_sh = quoted_sh
    )
}

fn is_permission_denied_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("unauthorizedaccessexception")
        || lower.contains("operation not permitted")
        || lower.contains("requires elevation")
        || message.contains("拒绝访问")
        || message.contains("无权")
        || message.contains("权限不足")
}

fn is_ignorable_bootstrap_stderr_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }

    let lower = trimmed.to_ascii_lowercase();
    if !lower.contains("powershell.exe") {
        return false;
    }

    lower.contains("command not found")
        || lower.contains("not found")
        || lower.contains("is not recognized")
        || trimmed.contains("未找到")
        || trimmed.contains("找不到")
}

fn is_ignorable_bootstrap_stderr_continuation(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    lower.contains("operable program or batch file")
}

fn sanitize_transfer_stderr(stderr: &str) -> String {
    let mut filtered = Vec::new();
    let mut previous_was_ignorable_bootstrap = false;

    for line in stderr.lines() {
        if is_ignorable_bootstrap_stderr_line(line) {
            previous_was_ignorable_bootstrap = true;
            continue;
        }

        if previous_was_ignorable_bootstrap && is_ignorable_bootstrap_stderr_continuation(line) {
            continue;
        }

        previous_was_ignorable_bootstrap = false;
        filtered.push(line);
    }

    filtered.join("\n")
}

fn has_meaningful_stderr(stderr: &str) -> bool {
    !sanitize_transfer_stderr(stderr).trim().is_empty()
}

fn transfer_error(operation: &str, stderr: &str) -> anyhow::Error {
    let sanitized = sanitize_transfer_stderr(stderr);
    let stderr = sanitized.trim();
    if stderr.is_empty() {
        anyhow!("{}失败：远程命令异常退出", operation)
    } else if is_permission_denied_message(stderr) {
        anyhow!("{}失败：无权访问目标路径（{}）", operation, stderr)
    } else {
        anyhow!("{}失败：{}", operation, stderr)
    }
}

fn wait_child_output(child: Child) -> Result<std::process::Output> {
    child
        .wait_with_output()
        .context("等待 SSH 子进程结束时失败")
}

fn build_unix_upload_script(final_remote_path: &str, is_dir_upload: bool) -> String {
    let path = quote_remote_path_for_sh(final_remote_path);
    let is_dir_upload = if is_dir_upload { "true" } else { "false" };

    let template = r#"
set -e
path=__PATH__
is_dir_upload=__IS_DIR_UPLOAD__

if [ "$is_dir_upload" = "true" ]; then
    if [ -e "$path" ] && [ ! -d "$path" ]; then
        echo "目标路径已存在且不是目录: $path" >&2
        exit 21
    fi

    if ! mkdir -p "$path" 2>/dev/null; then
        echo "无权创建或写入目标目录: $path" >&2
        exit 13
    fi

    probe="$path/.sshc_write_probe_$$"
    if ! : > "$probe" 2>/dev/null; then
        echo "无权写入目标目录: $path" >&2
        exit 13
    fi
    rm -f "$probe" >/dev/null 2>&1 || true
else
    if [ -d "$path" ]; then
        echo "目标路径是目录，无法覆盖为文件: $path" >&2
        exit 22
    fi

    parent="$(dirname "$path")"
    if ! mkdir -p "$parent" 2>/dev/null; then
        echo "无权创建或写入目标目录: $parent" >&2
        exit 13
    fi

    probe="$parent/.sshc_write_probe_$$"
    if ! : > "$probe" 2>/dev/null; then
        echo "无权写入目标目录: $parent" >&2
        exit 13
    fi
    rm -f "$probe" >/dev/null 2>&1 || true
fi

if command -v zstd >/dev/null 2>&1; then
    echo "COMPRESSION:zstd"
    decomp="zstd -d -q -c"
else
    echo "COMPRESSION:gzip"
    decomp="gzip -d"
fi

if [ "$is_dir_upload" = "true" ]; then
    cd "$path" || {
        echo "无权访问目标目录: $path" >&2
        exit 13
    }
    if ! eval "$decomp" | tar -xf -; then
        echo "写入目录失败或解包失败: $path" >&2
        exit 30
    fi
else
    if ! eval "$decomp" > "$path"; then
        echo "写入文件失败: $path" >&2
        exit 30
    fi
fi
"#;

    template
        .replace("__PATH__", &path)
        .replace("__IS_DIR_UPLOAD__", is_dir_upload)
}

fn build_powershell_upload_script(final_remote_path: &str, is_dir_upload: bool) -> String {
    let path = quote_remote_path_for_powershell(final_remote_path);
    let is_dir_upload = if is_dir_upload { "$true" } else { "$false" };

    let template = r#"
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 1 }
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$path = __PATH__
$isDirUpload = __IS_DIR_UPLOAD__

function Fail([string]$message) {
    [Console]::Error.WriteLine($message)
    exit 0
}

function Resolve-RemotePath([string]$rawPath) {
    if ($rawPath -eq '~') {
        return $HOME
    }
    if ($rawPath.StartsWith('~/') -or $rawPath.StartsWith('~\\')) {
        return Join-Path $HOME $rawPath.Substring(2)
    }
    return $rawPath
}

function Test-DirectoryWritable([string]$dirPath) {
    $probe = Join-Path $dirPath (".sshc_write_probe_{0}" -f ([guid]::NewGuid().ToString('N')))
    try {
        $stream = [System.IO.File]::Create($probe)
        $stream.Dispose()
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

$path = Resolve-RemotePath $path

if ($isDirUpload) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Fail "目标路径已存在且不是目录: $path"
    }

    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-DirectoryWritable $path)) {
        Fail "无权写入目标目录: $path"
    }
} else {
    if (Test-Path -LiteralPath $path -PathType Container) {
        Fail "目标路径是目录，无法覆盖为文件: $path"
    }

    $parent = Split-Path -Parent $path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = '.'
    }

    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-DirectoryWritable $parent)) {
        Fail "无权写入目标目录: $parent"
    }
}

[Console]::Out.WriteLine('COMPRESSION:gzip')
[Console]::Out.Flush()

$stdin = [Console]::OpenStandardInput()
$gzipStream = New-Object System.IO.Compression.GZipStream($stdin, [System.IO.Compression.CompressionMode]::Decompress)

try {
    if ($isDirUpload) {
        $tempTar = Join-Path ([System.IO.Path]::GetTempPath()) ("sshc_{0}.tar" -f ([guid]::NewGuid().ToString('N')))
        try {
            $tarOut = [System.IO.File]::Create($tempTar)
            try {
                $gzipStream.CopyTo($tarOut)
            } finally {
                $tarOut.Dispose()
            }

            & tar -xf $tempTar -C $path
            if ($LASTEXITCODE -ne 0) {
                throw "写入目录失败或系统未提供 tar.exe: $path"
            }
        } finally {
            Remove-Item -LiteralPath $tempTar -Force -ErrorAction SilentlyContinue
        }
    } else {
        $fileOut = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $gzipStream.CopyTo($fileOut)
        } finally {
            $fileOut.Dispose()
        }
    }
} catch [System.UnauthorizedAccessException] {
    Fail "无权写入目标路径: $path"
} catch {
    Fail $_.Exception.Message
} finally {
    $gzipStream.Dispose()
}
"#;

    template
        .replace("__PATH__", &path)
        .replace("__IS_DIR_UPLOAD__", is_dir_upload)
}

fn build_unix_download_script(remote_path: &str) -> String {
    let path = quote_remote_path_for_sh(remote_path);

    let template = r#"
set -e
path=__PATH__

if ls_result=$(ls -ld "$path" 2>&1); then
    :
else
    if echo "$ls_result" | grep -Eiq 'permission denied|access is denied|operation not permitted|拒绝访问|权限'; then
        echo "TYPE:access_denied"
        echo "ERROR:无权访问远程路径: $path"
    else
        echo "TYPE:not_found"
    fi
    echo "---DATA---"
    exit 0
fi

if [ -d "$path" ]; then
    if [ ! -r "$path" ] || [ ! -x "$path" ]; then
        echo "TYPE:access_denied"
        echo "ERROR:无权读取远程目录: $path"
        echo "---DATA---"
        exit 0
    fi

    echo "TYPE:dir"
    if uname | grep -q "Linux"; then
        if size=$(du -sb "$path" 2>/dev/null | cut -f1); then
            :
        else
            size=""
        fi
    else
        if kbytes=$(du -sk "$path" 2>/dev/null | cut -f1); then
            size=$((kbytes * 1024))
        else
            size=""
        fi
    fi

    if [ -z "$size" ]; then
        echo "TYPE:access_denied"
        echo "ERROR:无权遍历远程目录: $path"
        echo "---DATA---"
        exit 0
    fi

    echo "SIZE:$size"
    remote_type="dir"
elif [ -f "$path" ]; then
    if [ ! -r "$path" ]; then
        echo "TYPE:access_denied"
        echo "ERROR:无权读取远程文件: $path"
        echo "---DATA---"
        exit 0
    fi

    echo "TYPE:file"
    if size=$(wc -c < "$path" 2>/dev/null); then
        size=$(echo "$size" | tr -d '[:space:]')
    else
        size=""
    fi

    if [ -z "$size" ]; then
        echo "TYPE:access_denied"
        echo "ERROR:无法读取远程文件元信息: $path"
        echo "---DATA---"
        exit 0
    fi

    echo "SIZE:$size"
    remote_type="file"
else
    echo "TYPE:not_found"
    echo "---DATA---"
    exit 0
fi

if command -v zstd >/dev/null 2>&1; then
    echo "COMPRESSION:zstd"
    comp="zstd -1 -q -c"
else
    echo "COMPRESSION:gzip"
    comp="gzip -1 -c"
fi

echo "---DATA---"

if [ "$remote_type" = "dir" ]; then
    tar -cf - -C "$path" . | eval "$comp"
else
    cat "$path" | eval "$comp"
fi
"#;

    template.replace("__PATH__", &path)
}

fn build_powershell_download_script(remote_path: &str) -> String {
    let path = quote_remote_path_for_powershell(remote_path);

    let template = r#"
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 1 }
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$path = __PATH__

function Fail([string]$message) {
    [Console]::Error.WriteLine($message)
    exit 0
}

function Resolve-RemotePath([string]$rawPath) {
    if ($rawPath -eq '~') {
        return $HOME
    }
    if ($rawPath.StartsWith('~/') -or $rawPath.StartsWith('~\\')) {
        return Join-Path $HOME $rawPath.Substring(2)
    }
    return $rawPath
}

function Emit-TerminalMeta([string]$type, [string]$errorMessage) {
    [Console]::Out.WriteLine("TYPE:$type")
    if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
        [Console]::Out.WriteLine("ERROR:$errorMessage")
    }
    [Console]::Out.WriteLine('---DATA---')
    [Console]::Out.Flush()
}

$path = Resolve-RemotePath $path

try {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
} catch [System.UnauthorizedAccessException] {
    Emit-TerminalMeta 'access_denied' "无权访问远程路径: $path"
    exit 0
} catch [System.Management.Automation.ItemNotFoundException] {
    Emit-TerminalMeta 'not_found' $null
    exit 0
} catch {
    $msg = $_.Exception.Message
    if ($msg -match 'denied|拒绝|unauthor') {
        Emit-TerminalMeta 'access_denied' "无权访问远程路径: $path"
    } else {
        Emit-TerminalMeta 'not_found' $null
    }
    exit 0
}

if ($item.PSIsContainer) {
    try {
        $sizeMeasure = Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
    } catch [System.UnauthorizedAccessException] {
        Emit-TerminalMeta 'access_denied' "无权遍历远程目录: $path"
        exit 0
    }

    $size = [int64]0
    if ($null -ne $sizeMeasure.Sum) {
        $size = [int64]$sizeMeasure.Sum
    }

    $remoteType = 'dir'
} else {
    $size = [int64]$item.Length
    $remoteType = 'file'

    try {
        $probe = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $probe.Dispose()
    } catch [System.UnauthorizedAccessException] {
        Emit-TerminalMeta 'access_denied' "无权读取远程文件: $path"
        exit 0
    }
}

[Console]::Out.WriteLine("TYPE:$remoteType")
[Console]::Out.WriteLine("SIZE:$size")
[Console]::Out.WriteLine('COMPRESSION:gzip')
[Console]::Out.WriteLine('---DATA---')
[Console]::Out.Flush()

$stdout = [Console]::OpenStandardOutput()
$gzipStream = New-Object System.IO.Compression.GZipStream($stdout, [System.IO.Compression.CompressionMode]::Compress, $true)

try {
    if ($remoteType -eq 'dir') {
        $tempTar = Join-Path ([System.IO.Path]::GetTempPath()) ("sshc_{0}.tar" -f ([guid]::NewGuid().ToString('N')))
        try {
            & tar -cf $tempTar -C $path .
            if ($LASTEXITCODE -ne 0) {
                throw "读取目录失败或系统未提供 tar.exe: $path"
            }

            $tarIn = [System.IO.File]::OpenRead($tempTar)
            try {
                $tarIn.CopyTo($gzipStream)
            } finally {
                $tarIn.Dispose()
            }
        } finally {
            Remove-Item -LiteralPath $tempTar -Force -ErrorAction SilentlyContinue
        }
    } else {
        $fileIn = [System.IO.File]::OpenRead($item.FullName)
        try {
            $fileIn.CopyTo($gzipStream)
        } finally {
            $fileIn.Dispose()
        }
    }
} catch [System.UnauthorizedAccessException] {
    Fail "无权读取远程路径: $path"
} catch {
    Fail $_.Exception.Message
} finally {
    $gzipStream.Dispose()
}
"#;

    template.replace("__PATH__", &path)
}

fn build_upload_remote_command(final_remote_path: &str, is_dir_upload: bool) -> String {
    let unix_script = build_unix_upload_script(final_remote_path, is_dir_upload);
    let powershell_script = build_powershell_upload_script(final_remote_path, is_dir_upload);
    build_dual_shell_command(&powershell_script, &unix_script)
}

fn build_download_remote_command(remote_path: &str) -> String {
    let unix_script = build_unix_download_script(remote_path);
    let powershell_script = build_powershell_download_script(remote_path);
    build_dual_shell_command(&powershell_script, &unix_script)
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

    let remote_command = build_upload_remote_command(&final_remote_path, is_dir_upload);

    let mut child = SshProcessBuilder::new(server, &remote_command).spawn_for_io()?;

    let ssh_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("无法获取 SSH 进程的 stdout"))?;
    let mut reader = BufReader::new(ssh_stdout);

    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        let output = wait_child_output(child)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(transfer_error("上传", &stderr));
    }

    let algorithm = match line.trim() {
        "COMPRESSION:zstd" => {
            info!("服务器选择 zstd 压缩算法。");
            CompressionAlgorithm::Zstd
        }
        "COMPRESSION:gzip" => {
            info!("服务器选择 gzip 压缩算法。");
            CompressionAlgorithm::Gzip
        }
        _ => {
            let output = wait_child_output(child)?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            if has_meaningful_stderr(&stderr) {
                return Err(transfer_error("上传", &stderr));
            }
            return Err(anyhow!("从服务器收到了无效的压缩协商响应: {}", line.trim()));
        }
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

    let transfer_result: Result<()> = match algorithm {
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
            Ok(())
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
            Ok(())
        }
    };

    let output = wait_child_output(child)?;

    if let Err(err) = transfer_result {
        pb.abandon_with_message("上传失败");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if has_meaningful_stderr(&stderr) {
            return Err(transfer_error("上传", &stderr));
        }
        return Err(err).context("上传数据流写入失败");
    }

    if !output.status.success() {
        pb.abandon_with_message("上传失败");
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(transfer_error("上传", &stderr));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if has_meaningful_stderr(&stderr) {
        pb.abandon_with_message("上传失败");
        return Err(transfer_error("上传", &stderr));
    }

    pb.finish_with_message("上传完成");
    Ok(())
}

pub fn download(server: &Server, remote_path_str: &str, local_path: &Path) -> Result<()> {
    let remote_command = build_download_remote_command(remote_path_str);

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
            let output = wait_child_output(child)?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            if has_meaningful_stderr(&stderr) {
                return Err(transfer_error("下载", &stderr));
            }
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
                    "not_found" => meta.path_type = RemotePathType::NotFound,
                    "access_denied" => meta.path_type = RemotePathType::AccessDenied,
                    _ => return Err(anyhow!("未知的远程路径类型: {}", value)),
                },
                "SIZE" => meta.size = value.parse().context("解析远程文件大小时失败")?,
                "COMPRESSION" => match value {
                    "zstd" => meta.compression = CompressionAlgorithm::Zstd,
                    "gzip" => meta.compression = CompressionAlgorithm::Gzip,
                    _ => return Err(anyhow!("未知的压缩算法: {}", value)),
                },
                "ERROR" => meta.error_message = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    match meta.path_type {
        RemotePathType::NotFound => {
            let _ = wait_child_output(child);
            return Err(anyhow!("远程路径未找到: {}", remote_path_str));
        }
        RemotePathType::AccessDenied => {
            let _ = wait_child_output(child);
            let message = meta
                .error_message
                .unwrap_or_else(|| format!("无权访问远程路径: {}", remote_path_str));
            return Err(anyhow!(message));
        }
        RemotePathType::File | RemotePathType::Directory => {}
    }

    info!(
        "成功解析远程元数据: 类型={:?}, 大小={}, 压缩={:?}",
        meta.path_type, meta.size, meta.compression
    );

    let trimmed_remote_path = remote_path_str.trim_end_matches(|c| c == '/' || c == '\\');
    let remote_base_name = Path::new(trimmed_remote_path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
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

    let buffered_bytes = reader.buffer().to_vec();
    let underlying_stream = reader.into_inner();
    let chained_reader = io::Cursor::new(buffered_bytes).chain(underlying_stream);

    let decompressor: Box<dyn Read> = match meta.compression {
        CompressionAlgorithm::Gzip => Box::new(GzDecoder::new(chained_reader)),
        CompressionAlgorithm::Zstd => Box::new(zstd::stream::Decoder::new(chained_reader)?),
    };

    let mut progress_reader = pb.wrap_read(decompressor);

    let data_result: Result<()> = match meta.path_type {
        RemotePathType::File => {
            if let Some(parent) = final_local_path.parent() {
                fs::create_dir_all(parent).context("创建本地父目录失败")?;
            }
            let mut dest_file = File::create(&final_local_path).context("创建本地文件失败")?;
            io::copy(&mut progress_reader, &mut dest_file)?;
            Ok(())
        }
        RemotePathType::Directory => {
            fs::create_dir_all(&final_local_path).context("创建本地目标目录失败")?;
            let mut archive = tar::Archive::new(progress_reader);
            archive
                .unpack(&final_local_path)
                .context("解包 tar 归档失败")?;
            Ok(())
        }
        RemotePathType::NotFound | RemotePathType::AccessDenied => unreachable!(),
    };

    let output = wait_child_output(child)?;

    if let Err(err) = data_result {
        pb.abandon_with_message("下载失败");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if has_meaningful_stderr(&stderr) {
            return Err(transfer_error("下载", &stderr));
        }
        return Err(err).context("下载数据流读取失败");
    }

    if !output.status.success() {
        pb.abandon_with_message("下载失败");
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(transfer_error("下载", &stderr));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if has_meaningful_stderr(&stderr) {
        pb.abandon_with_message("下载失败");
        return Err(transfer_error("下载", &stderr));
    }

    pb.finish_with_message("下载完成");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_unix_download_script, build_unix_upload_script, has_meaningful_stderr,
        sanitize_transfer_stderr,
    };

    #[test]
    fn ignores_powershell_not_found_noise() {
        let stderr = "bash: line 1: powershell.exe: command not found\n/bin/sh: 1: powershell.exe: not found\n";
        assert!(!has_meaningful_stderr(stderr));
        assert_eq!(sanitize_transfer_stderr(stderr), "");
    }

    #[test]
    fn keeps_real_stderr() {
        let stderr = "bash: line 1: powershell.exe: command not found\n无权写入目标目录: /root\n";
        assert!(has_meaningful_stderr(stderr));
        assert_eq!(sanitize_transfer_stderr(stderr), "无权写入目标目录: /root");
    }

    #[test]
    fn ignores_windows_cmd_powershell_not_recognized_noise() {
        let stderr = "'powershell.exe' is not recognized as an internal or external command,\noperable program or batch file.\n";
        assert!(!has_meaningful_stderr(stderr));
        assert_eq!(sanitize_transfer_stderr(stderr), "");
    }

    #[test]
    fn unix_upload_script_prefers_zstd_when_available() {
        let script = build_unix_upload_script("~/dest", true);
        assert!(script.contains("command -v zstd >/dev/null 2>&1"));
        assert!(script.contains("echo \"COMPRESSION:zstd\""));
        assert!(script.contains("decomp=\"zstd -d -q -c\""));
    }

    #[test]
    fn unix_download_script_prefers_zstd_when_available() {
        let script = build_unix_download_script("~/src");
        assert!(script.contains("command -v zstd >/dev/null 2>&1"));
        assert!(script.contains("echo \"COMPRESSION:zstd\""));
        assert!(script.contains("comp=\"zstd -1 -q -c\""));
    }
}
