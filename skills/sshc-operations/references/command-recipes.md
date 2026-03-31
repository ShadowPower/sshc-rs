# sshc command recipes

Use this reference when you need concrete command syntax for sshc-rs.

## Connect

```bash
sshc
sshc c prod-server
sshc f prod-server
```

## Configure hosts

```bash
# Add a host (prompt password securely)
sshc config add prod -h 192.168.1.100 -u admin -P -n "Production"

# Add with local port forwarding
sshc config add db -h 10.0.0.5 -u root -P -L 5433:localhost:5432

# Edit an existing host
sshc config edit prod -p 2222 --x11

# Show host config
sshc config show prod
```

## Run remote commands

```bash
# Single host
sshc run prod -- uname -a

# Group
sshc run @backend -- systemctl status nginx

# All hosts in parallel
sshc run all -p -- uptime

# Elevated command
sshc run sudo prod -- systemctl restart nginx
```

## Interactive TTY

```bash
sshc tty prod -- vim /etc/nginx/nginx.conf
sshc tty prod -- top
sshc tty sudo prod -- htop
```

## Transfer files

```bash
# Upload file
sshc up ./local-file.txt my-server:~/remote-file.txt

# Upload directory
sshc up ./dist my-server:/var/www/html/

# Download file
sshc down my-server:/var/log/app.log ./

# Download directory
sshc down my-server:/etc/nginx ./nginx-backup/
```

## Web UI

```bash
sshc w
sshc w --bind 0.0.0.0 --port 8080
sshc w --no-browser
```

## JSON API

```bash
sshc api list
sshc api get prod
echo '{"name":"new","server":{"host":"1.2.3.4","user":"root"}}' | sshc api set
sshc api rm old-server
```

## Diagnostics and migration

```bash
sshc doctor
sshc doctor prod

sshc export
sshc import '<exported-data>'
```
