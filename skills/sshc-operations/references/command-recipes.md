# sshc command recipes

Use this reference for concrete, ready-to-run command syntax.

## Discover targets and connect

```bash
# Default target discovery (human-readable)
sshc list
sshc l

# Interactive SSH picker
sshc

# Direct SSH by saved name
sshc c prod-server

# FileZilla/SFTP
sshc f prod-server
```

## Run remote commands (non-interactive)

```bash
# Single host
sshc run prod -- uname -a

# Preferred flow: check NAS time
sshc list
sshc run nas -- date

# Group target
sshc run @backend -- systemctl status nginx

# All targets (serial by default)
sshc run @@all -- uptime

# Parallel read-only check
sshc run @@all -p -- "df -h"

# Target forms: exact host name, @group, @@all
```

## Elevated commands (sudo)

**IMPORTANT**: `sudo` is a subcommand of `run`/`tty`, NOT a prefix inside the remote command. Always use `sshc run sudo` or `sshc tty sudo` when the remote command requires root privileges.

```bash
# Restart/stop/start a service (needs root)
sshc run sudo prod -- systemctl restart nginx
sshc run sudo prod -- systemctl stop apache2

# Install/remove packages (needs root)
sshc run sudo prod -- apt update && apt upgrade -y
sshc run sudo @backend -p -- yum install -y htop

# Edit system config files (needs root)
sshc tty sudo prod -- vim /etc/nginx/nginx.conf
sshc run sudo prod -- cp /etc/hosts /etc/hosts.bak

# Docker operations requiring root
sshc run sudo prod -- systemctl restart docker
sshc run sudo prod -- docker compose up -d

# Network/firewall changes (needs root)
sshc run sudo prod -- ufw allow 8080/tcp
sshc run sudo prod -- firewall-cmd --add-port=8080/tcp --permanent

# File operations on protected paths (needs root)
sshc run sudo prod -- chown www-data:www-data /var/www/html/index.html
sshc run sudo prod -- chmod 644 /etc/myapp/config.toml

# System control (needs root)
sshc run sudo prod -- reboot
sshc run sudo prod -- shutdown -h now

# Group with sudo in parallel (e.g., update all backend servers)
sshc run sudo @backend -p -- apt update
```

## Interactive commands (TTY)

```bash
# TTY is for full-screen/interactive apps and requires exact host name
sshc tty prod -- vim /etc/nginx/nginx.conf
sshc tty prod -- top
sshc tty sudo prod -- htop
```

## File transfer

```bash
# Upload file and keep original name in remote home
sshc up ./local-file.txt my-server:

# Upload file and rename
sshc up ./config.yaml my-server:~/app.yaml

# Upload directory to target directory
sshc up ./dist my-server:/var/www/html/

# Download file to current directory
sshc down my-server:/var/log/app.log .

# Download directory
sshc down my-server:/etc/nginx ./nginx-backup/
```

## Configure hosts and groups

```bash
# Add host (secure password prompt)
sshc config add prod -h 192.168.1.100 -u admin -P -n "Production"

# Add host with forwards
sshc config add db -h 10.0.0.5 -u root -P -L 5433:localhost:5432 -R 8080:localhost:80 -D 1080

# Edit host fields
sshc config edit prod -p 2222 --x11

# Clear existing forwards while editing
sshc config edit prod --clear-forwards

# Show host config (human-readable)
sshc config show prod

# Remove host (interactive confirmation)
sshc config remove old-server

# Group management
sshc config group list
sshc config group add backend
sshc config group rename backend core-backend
sshc config group remove core-backend
```

## JSON API (automation only)

```bash
# List host names as JSON array
sshc api list

# Get one host as JSON
sshc api get prod

# Get all hosts as JSON map
sshc api get

# Set from stdin JSON payload
echo '{"name":"new","server":{"host":"1.2.3.4","user":"root"}}' | sshc api set

# Set from --data
sshc api set -d '{"name":"new2","server":{"host":"1.2.3.5","user":"admin"}}'

# Remove without prompt
sshc api rm old-server
```

## Web UI, diagnosis, migration

```bash
# Web manager
sshc w
sshc w --bind 0.0.0.0 --port 8080
sshc w --no-browser

# Diagnose local + remote checks
sshc doctor
sshc doctor prod

# Export/import all config
sshc export
sshc import '<exported-data>'
```

## Common operation playbooks

```bash
# Inspect system time and uptime (no sudo needed — read-only)
sshc run prod -- date
sshc run prod -- uptime

# Check resource usage (no sudo needed — read-only)
sshc run @backend -p -- "df -h"
sshc run @backend -p -- "free -m"

# Restart service on one host (needs sudo), then verify (no sudo)
sshc run sudo prod -- systemctl restart nginx
sshc run prod -- systemctl status nginx --no-pager

# Install a package (needs sudo)
sshc run sudo prod -- apt install -y curl

# Edit a system config file interactively (needs sudo)
sshc tty sudo prod -- vim /etc/ssh/sshd_config

# Update all backend servers in parallel (needs sudo)
sshc run sudo @backend -p -- apt update && apt upgrade -y

# Tail logs interactively (may or may not need sudo depending on log path)
sshc tty prod -- "tail -f /var/log/nginx/error.log"
sshc tty sudo prod -- "tail -f /var/log/auth.log"
```
