# sshc - 现代化的 SSH 连接管理器

[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green.svg)]()

一个功能强大、易于使用的 SSH 连接管理器，用 Rust 编写。提供**终端界面 (TUI)**、**Web UI**、**命令行** 和 **JSON API** 四种操作方式，让你管理服务器连接从未如此轻松。

## 特性亮点

- **多种界面** - TUI 交互式列表、Web 图形界面、命令行操作、JSON API
- **一键连接** - 无需记忆 IP、用户名、密码，选即连
- **批量执行** - 在多台服务器上并行或串行执行命令
- **安全传输** - 支持压缩的文件上传/下载，带进度条
- **自动提权** - sudo 命令自动处理密码，无需交互
- **端口转发** - 支持本地、远程、动态 (SOCKS) 转发
- **配置迁移** - 一条命令导入导出所有配置
- **密码加密** - 可选的密码加密存储
- **跨平台** - 支持 Linux、Windows、macOS
- **零依赖** - 单一二进制文件，开箱即用

## 快速开始

### 安装

从 [Releases](../../releases) 页面下载对应平台的二进制文件，或自行编译：

```bash
git clone https://github.com/user/sshc-rs.git
cd sshc-rs
cargo build --release
```

### 基本用法

```bash
# 交互式选择服务器连接 (最常用)
sshc

# 直接连接指定服务器
sshc c my-server

# 列出所有服务器
sshc l

# 在服务器上执行命令
sshc run my-server -- uname -a

# 上传文件
sshc up ./file.txt my-server:/path/to/dest/

# 启动 Web 管理界面
sshc w
```

### Agent Skill 安装

本仓库内置了可安装 Skill：`sshc-operations`（路径：`skills/sshc-operations`）。

```bash
# 查看仓库中可安装的 skills
npx skills add ShadowPower/sshc-rs --list

# 从 GitHub 安装 skill
npx skills add ShadowPower/sshc-rs

# 本地仓库调试安装
npx skills add . --skill sshc-operations
```

## 功能详解

### 交互式连接 (TUI)

```bash
sshc        # SSH 连接
sshc f      # FileZilla SFTP 连接
```

- 自适应终端高度
- 方向键选择，字符实时筛选
- 简单直观，无需记忆

### 配置管理

```bash
# 添加服务器
sshc config add prod -h 192.168.1.100 -u admin -P -n "生产服务器"

# 添加带端口转发的服务器
sshc config add db -h 10.0.0.5 -u root -P -L 5433:localhost:5432

# 修改配置
sshc config edit prod -p 2222 --x11

# 查看配置
sshc config show prod

# 删除配置
sshc config remove old-server
```

### 批量命令执行

```bash
# 单台服务器
sshc run prod-server -- df -h

# 整个分组
sshc run @backend -- systemctl status nginx

# 所有服务器
sshc run @@all -- uptime

# 并行执行
sshc run @web -p -- "nginx -t"

# sudo 提权执行
sshc run sudo prod -- systemctl restart nginx
```

### 交互式命令 (TTY)

适合 `vim`、`top`、`htop`、`less` 等需要实时交互的程序：

```bash
sshc tty prod -- vim /etc/nginx/nginx.conf
sshc tty prod -- top
sshc tty sudo prod -- htop
```

### 文件传输

```bash
# 上传
sshc up ./local-file.txt server:~/remote-file.txt
sshc up ./dist server:/var/www/html/

# 下载
sshc down server:/var/log/app.log ./
sshc down server:/etc/nginx ./nginx-backup/
```

- 支持 zstd/gzip 压缩
- 实时进度条
- 自动处理目录结构

### Web 管理界面

```bash
sshc w                           # 启动并自动打开浏览器
sshc w --bind 0.0.0.0 --port 8080  # 局域网访问
sshc w --no-browser              # 不自动打开浏览器
```

### 配置迁移

```bash
# 导出配置
sshc export
# 输出: sshc import 'Base85编码的压缩数据...'

# 在新机器导入
sshc import '...'
```

### JSON API (脚本集成)

```bash
# 列出所有服务器名称
sshc api list

# 获取服务器配置
sshc api get prod-server

# 添加/更新服务器
echo '{"name":"new","server":{"host":"1.2.3.4","user":"root"}}' | sshc api set
```

### 诊断工具

```bash
sshc doctor           # 检查本地环境
sshc doctor prod-server  # 额外检查服务器连通性
```

## 配置文件

配置存储在 `~/.sshc/config.toml`：

```toml
[servers.prod]
host = "192.168.1.100"
user = "admin"
port = 22
display_name = "生产服务器"
group = "production"
password_encrypted = "..."

[servers.prod.port_forwards]
[[servers.prod.port_forwards]]
type = "Local"
local_port = 5433
remote_host = "localhost"
remote_port = 5432
```

## 命令速查

| 命令 | 说明 |
|------|------|
| `sshc` | 交互式 SSH 连接 |
| `sshc f` | 交互式 FileZilla 连接 |
| `sshc c <name>` | 直接 SSH 连接 |
| `sshc l` | 列出所有服务器 |
| `sshc w` | 启动 Web UI |
| `sshc config add/edit/show/remove` | 配置管理 |
| `sshc run [sudo] <target> -- <cmd>` | 批量执行命令 |
| `sshc tty [sudo] <name> -- <cmd>` | 交互式执行 |
| `sshc up/down` | 文件传输 |
| `sshc api list/get/set/rm` | JSON API |
| `sshc export/import` | 配置迁移 |
| `sshc doctor` | 环境诊断 |
| `sshc tutorial` | 完整教程 |

## 构建

```bash
# 开发构建
cargo build

# 发布构建 (优化体积)
cargo build --release
```

## 许可证

[MIT License](LICENSE)
