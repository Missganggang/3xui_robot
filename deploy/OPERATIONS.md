# Debian 原生部署与维护

本指南采用 Debian 12、Python 3.11+、systemd 和 nginx。应用使用专用系统账户，后端仅监听 `127.0.0.1:18080`；nginx 提供 HTTPS。文中的 `203.0.113.10` 是文档专用地址，必须替换为自己的公网 IP。网站主机与客户要安装 3x-ui 的目标服务器可以不同。

使用域名及 Docker 的部署方式见 [README](../README.md)。下文的 IP 入口使用支持 IP 地址证书的 Certbot 和 Let's Encrypt `shortlived` 配置，不需要 Cloudflare Token。

## 1. 准备环境和源码

以下命令由 root 执行。先检查端口和现有服务；80/443 被占用时，应将本站接入已有反向代理，不要直接覆盖其站点。后端端口 `18080` 也需要空闲。

```bash
ss -lntp
apt-get update
apt-get install -y git python3-venv nginx ca-certificates
useradd --system --home-dir /var/lib/3xui-console --no-create-home --shell /usr/sbin/nologin xui-console
install -d -m 0755 /opt/3xui-console/releases
git clone https://github.com/Missganggang/3xui_robot.git /opt/3xui-console/releases/initial
ln -s /opt/3xui-console/releases/initial /opt/3xui-console/current
python3 -m venv /opt/3xui-console/venv
/opt/3xui-console/venv/bin/python -m pip install -r /opt/3xui-console/current/requirements.txt
install -d -m 0700 -o xui-console -g xui-console /var/lib/3xui-console
```

如果账户、目录或链接已经存在，先核实其用途，再复用或选择新的发布目录；不要直接重复覆盖。

| 内容 | 路径 |
| --- | --- |
| 当前程序 | `/opt/3xui-console/current`，链接至 `releases/<version>` |
| Python 环境 | `/opt/3xui-console/venv/` |
| 私有环境配置 | `/etc/3xui-console.env` |
| 数据库、上传及主机指纹 | `/var/lib/3xui-console/` |
| ACME 验证目录 | `/var/lib/3xui-console-acme/` |
| Certbot 环境 | `/opt/3xui-console/certbot/` |
| IP 证书 | `/etc/letsencrypt/live/3xui-console-ip/` |

## 2. 私有配置和管理员

生成密钥并写入 root 私有环境文件；此文件不放在 Git 工作区内。

```bash
umask 077
/opt/3xui-console/venv/bin/python - <<'PY'
from pathlib import Path
import secrets
path = Path('/etc/3xui-console.env')
with path.open('x', encoding='utf-8') as output:
    output.write('APP_SECRET=' + secrets.token_urlsafe(48) + '\n')
    output.write('DATA_DIR=/var/lib/3xui-console\n')
    output.write('COOKIE_SECURE=true\n')
    output.write('ALLOWED_HOSTS=203.0.113.10,127.0.0.1,localhost\n')
    output.write('ENABLE_WORKER=true\n')
    output.write('ALLOW_PRIVATE_TARGETS=false\n')
    output.write('MAX_CONCURRENT_JOBS=2\n')
    output.write('UPLOAD_RETENTION_HOURS=24\n')
path.chmod(0o600)
PY
editor /etc/3xui-console.env
```

将 `ALLOWED_HOSTS` 中的示例 IP 替换为自己的 IP。绑定网站域名时加入该域名；这里不是客户的面板域名。密钥生成脚本使用独占创建，已存在的配置文件不会被覆盖。

全新站点创建管理员，密码在终端交互输入，至少 12 位，无默认管理员密码：

```bash
cd /opt/3xui-console/current
set -a
. /etc/3xui-console.env
set +a
runuser -u xui-console --preserve-environment -- /opt/3xui-console/venv/bin/python -m app.cli create-admin admin
```

环境文件由 systemd 读取，保持目录外置、root 所有、权限 `600`。数据目录归 `xui-console:xui-console`，目录 `700`、敏感文件 `600`。程序、venv 和发布链接由 root 管理，网站账户只需读取。不能把 `.env`、数据库、证书私钥或上传文件放入 nginx 静态目录。

如果是迁入已有工作台，跳过密钥生成和创建管理员，按后文“迁移、备份与恢复”保留原 `APP_SECRET` 和数据。改变密钥会导致原 Cloudflare Token 无法解密。

## 3. 启动应用

```bash
cd /opt/3xui-console/current
install -m 0644 deploy/3xui-console.service /etc/systemd/system/3xui-console.service
systemd-analyze verify /etc/systemd/system/3xui-console.service
systemctl daemon-reload
systemctl enable --now 3xui-console.service
curl --fail http://127.0.0.1:18080/api/ready
```

`/api/health` 检查网站存活；`/api/ready` 在执行器可接任务时返回 200，暂停或异常时返回 503。诊断命令：

```bash
systemctl status 3xui-console.service --no-pager
journalctl -u 3xui-console.service -n 100 --no-pager
```

服务只使用一个 Uvicorn worker，不使用 `--reload`。隔离设置包括 `NoNewPrivileges`、`PrivateTmp`、`ProtectHome`、`ProtectSystem=strict`，可写业务目录限于 `/var/lib/3xui-console`。目标主机操作通过客户 SSH 信息完成，网站进程无需本机 root 权限。

## 4. 签发 IP 证书

确认公网 TCP 80/443 可达，建立独立的 ACME webroot：

```bash
install -d -m 0755 /var/lib/3xui-console-acme/.well-known/acme-challenge
```

首次签发前，先在 nginx 新站点中启用以下 HTTP 配置，将示例 IP 替换为自己的 IP。不要引用尚不存在的证书。

```nginx
server {
    listen 80;
    server_name 203.0.113.10;
    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/3xui-console-acme;
        default_type text/plain;
        try_files $uri =404;
    }
    location / { return 503; }
}
```

保存为 `/etc/nginx/sites-available/3xui-console`，建立启用链接，再验证并加载：

```bash
ln -s /etc/nginx/sites-available/3xui-console /etc/nginx/sites-enabled/3xui-console
nginx -t
systemctl enable --now nginx
systemctl reload nginx
```

ACME 目录应允许 nginx 遍历和读取（目录 `755`、文件 `644`），不能使用业务数据目录的 `700` 权限。确保挑战路径可从公网读取后签发；示例 IP 不可用于真实签发。

```bash
python3 -m venv /opt/3xui-console/certbot
/opt/3xui-console/certbot/bin/python -m pip install 'certbot>=5.9,<6'
/opt/3xui-console/certbot/bin/certbot certonly \
  --non-interactive --agree-tos --register-unsafely-without-email \
  --webroot -w /var/lib/3xui-console-acme \
  --required-profile shortlived --ip-address 203.0.113.10 \
  --cert-name 3xui-console-ip
```

此示例未配置邮箱通知，可改用自己登记的 ACME 账号邮箱。确认签发成功、证书含正确 IP，再安装完整 nginx 配置：

```bash
sed 's/203\.0\.113\.10/YOUR_PUBLIC_IP/g' deploy/nginx-ip.conf > /etc/nginx/sites-available/3xui-console
editor /etc/nginx/sites-available/3xui-console
nginx -t
systemctl reload nginx
```

把 `YOUR_PUBLIC_IP` 替换为真实 IP。浏览器从 `https://<你的公网IP>` 访问。HTTP 除挑战路径外跳转到 HTTPS，应用使用 Secure、HttpOnly、SameSite=Strict 会话 Cookie。

nginx 模板放行 `52m` 请求体，为 50 MiB 数据库的 multipart 留余量；应用仍限制单文件 50 MiB、整请求 51 MiB。反代覆盖客户端伪造的转发头，应用仅信任 `127.0.0.1`。API、HTML 不缓存，静态资源保留版本查询串。

## 5. 自动续期

IP 证书有效期短，必须启用自动续期。仓库提供每 6 小时检查的专用 systemd 单元：

```bash
install -m 0644 deploy/3xui-console-certbot.service /etc/systemd/system/
install -m 0644 deploy/3xui-console-certbot.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now 3xui-console-certbot.timer
systemctl list-timers 3xui-console-certbot.timer --all
/opt/3xui-console/certbot/bin/certbot renew --dry-run \
  --no-random-sleep-on-renew --cert-name 3xui-console-ip
```

成功续期后先检查 nginx 配置再重新加载，不重启网站进程。不要周期性强制签发；保持公网 80 和挑战路径可用。证书服务以 root 运行，与网站账户分开。私钥不授予网站进程读取。

```bash
systemctl start 3xui-console-certbot.service
journalctl -u 3xui-console-certbot.service -n 50 --no-pager
openssl x509 -in /etc/letsencrypt/live/3xui-console-ip/fullchain.pem -noout -dates
```

## 6. Cloudflare 配置

使用刚创建的管理员登录，进入“域名与 DNS”，输入自己的 Account ID 和最小权限 API Token，保存并验证。Token 加密写入私有 SQLite，不写入源码、环境模板或文档；安装者需要自行配置，仓库不附带任何可用令牌或账号。

管理员在“客户管理”分配域名，新客户默认没有域名权限。具体操作见 [使用指南](../docs/USAGE.md)。IP 站点 HTTPS 的签发与此 Token 无关；客户面板证书仍采用 HTTP-01。

## 7. 迁移、备份与恢复

1. 暂停新建及重试，等待 `queued`、`running` 均清零，再停止源执行器。可设置 `ENABLE_WORKER=false`，但它只暂停安装/迁移，账号及 DNS 管理仍可操作；数据快照期间需停止全部写入。
2. 使用 SQLite backup API 生成一致快照，或停源并 checkpoint 后复制。不能只复制活跃主数据库而遗漏 WAL。
3. 同时保留 `uploads/`、`ssh/known_hosts` 和原 `APP_SECRET`。原密钥用于解密 Token；密钥和数据备份分开妥善保管。
4. 数据库 `tasks.upload_path` 是绝对路径。换系统或目录后，重写为新目录下对应文件的绝对路径，并核对文件存在。上传文件 mtime 影响 24 小时清理。
5. 修正所有者与权限，使用支持可靠文件锁的本地磁盘；SQLite、指纹、`worker.lock`、`dns-locks/` 需服务账户可写。不要删除正在使用的锁文件。
6. 首次启动可先关闭执行器，检查账号、任务历史及 Cloudflare 解密，再开启。两台服务器的锁不能防止跨主机重复执行，不要同时启用同一队列的两个副本。

备份示例（root 执行，备份含敏感业务数据，保留在站点目录之外）：

```bash
install -d -m 0700 /var/backups/3xui-console
umask 077
systemctl stop 3xui-console.service
tar -czf /var/backups/3xui-console/data-$(date +%Y%m%d-%H%M%S).tar.gz -C /var/lib 3xui-console
systemctl start 3xui-console.service
```

另行安全备份 `/etc/3xui-console.env` 和 `/etc/letsencrypt`。恢复时停服务，恢复一致数据和原密钥，修正权限后重启并检查 `/api/ready`。不要把备份、数据库或加密 Token 提交到 Git；`.gitignore` 和 `.dockerignore` 已排除这些路径。

## 8. 更新与排错

新版本放到新的 `releases/<version>`，安装依赖并测试，等待活动任务清零后停止服务，备份数据，再切换 `current` 并启动。共享 venv 的更新可能影响旧版回退，记录依赖版本并核对数据库兼容性，回退程序不能覆盖更新后的业务数据。

```bash
systemctl restart 3xui-console.service
curl --fail http://127.0.0.1:18080/api/ready
nginx -t
journalctl -u 3xui-console.service -n 100 --no-pager
```

重启网站会取消活动远程任务并标记中断，不保证已执行修改自动回滚，不应定时重启网站。任务详情提供阶段错误和心跳日志；历史任务重试沿用原 IP 和域名，换目标需要新建任务。

网站服务器需能访问 Cloudflare、公共 DoH 服务以及客户 SSH 端口；客户目标服务器需能访问 GitHub、软件源和证书签发服务。更多验收项见 [验收清单](../docs/acceptance.md)。
