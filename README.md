# 3X Deploy · 3x-ui 部署与迁移工作台

面向管理员和客户的中文网站，通过 SSH 在客户服务器上部署 **3x-ui v2.9.4 / v3.4.2**，完成域名检查、SSL 证书、BBR 和交付验收；也支持上传 `x-ui.db` 做同版本迁移。

技术栈：Python 3.11+、FastAPI、SQLite 持久任务队列、AsyncSSH、原生 JavaScript，无需前端构建。

- [管理员与客户使用说明](docs/USAGE.md)
- [Linux 原生部署与维护](deploy/OPERATIONS.md)
- [服务器验收清单](docs/acceptance.md)

## 功能

- 管理员创建、启用、停用客户账号；客户只能访问自己的任务和明确分配的域名。
- Cloudflare 域名授权与 DNS 管理：A / AAAA / CNAME / TXT / MX 增改删，其他类型只读；每个域名最多新增至 100 条，达到上限后仍可编辑、删除已有记录。
- 新装面板端口默认随机，可选自定义端口。迁移使用随机或自定义临时安装端口，最终恢复旧数据库中的端口和入口路径。
- 检查 Ubuntu / Debian、root、默认 systemd + SQLite 安装环境，拒绝内网、回环和云元数据目标。
- 自动记录 SSH 主机公钥；指纹变化时自动更新对应 IP 与 SSH 端口的记录并继续，日志保留旧、新 SHA-256 指纹，无需手动确认。
- 域名 A / AAAA、端口、HTTPS、服务与 BBR 检查，自动申请和续期面板证书。系统 DNS 与目标不符时，使用 AliDNS、DNSPod 两家 DoH 核对完整 A / AAAA 结果。
- SQLite 文件完整性与源版本校验、安装前备份、上传哈希校验及原子替换；失败尝试恢复，任务中断后明确标记。
- 后台任务、阶段日志、排队信息、失败重试和同服务器互斥；SSH 密码临时加密保存，任务结束后清除。

新部署的面板用户名和密码均为 **`qqqzzz`**，入口路径随机生成，交付后请及时修改。网站账号与面板账号分开，网站密码至少 12 位，无默认网站管理员密码。迁移保留旧面板账号、密码、双重验证、入口路径、端口和节点配置，不展示或重置旧密码。

## 本地运行

在项目根目录执行，以下示例使用 Linux/macOS：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
.venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"
```

将生成的随机值保存为本地 `.env` 中的 `APP_SECRET`。仅在本机 HTTP 调试时设置 `COOKIE_SECURE=false`，再创建自己的管理员账号并启动：

```bash
.venv/bin/python -m app.cli create-admin site-admin
.venv/bin/python -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

打开 [本地工作台](http://127.0.0.1:8000)。管理员密码通过交互输入，不放在命令行参数中；`site-admin` 仅为示例用户名。

Windows PowerShell 使用 `python -m venv .venv`、`Copy-Item .env.example .env`，并将上述 `.venv/bin/python` 替换为 `.\.venv\Scripts\python.exe`。

重置网站账号密码：

```bash
.venv/bin/python -m app.cli reset-password site-admin
```

重置密码或停用客户会使其已有会话失效。

## 配置与敏感数据

环境变量示例见 [.env.example](.env.example)。

| 变量 | 用途 |
| --- | --- |
| `APP_SECRET` | 至少 32 位随机密钥；用于会话签名及 SSH 密码、Cloudflare Token 的加解密。首次生成后持久保存，迁移数据时保持原值。 |
| `DATA_DIR` | 持久目录，默认 `./data`；生产使用绝对路径，保存网站 SQLite、客户上传文件和 SSH 指纹。 |
| `COOKIE_SECURE` | 正式 HTTPS 为 `true`；仅本机 HTTP 调试可设 `false`。 |
| `ALLOWED_HOSTS` | 网站自己的域名或 IP，逗号分隔；保留 `127.0.0.1` 供健康检查，不填写客户面板域名。 |
| `ENABLE_WORKER` | `true` 启用安装/迁移；`false` 时登录、账号、DNS 和历史仍可用，新建及重试任务返回 503。 |
| `MAX_CONCURRENT_JOBS` | 单进程同时处理的不同服务器任务数，默认 2，范围 1–8。 |
| `UPLOAD_RETENTION_HOURS` | 已结束任务的上传文件保留小时数，默认 24；目标服务器备份不自动删除。 |
| `ALLOW_PRIVATE_TARGETS` | 公网站点保持 `false`。 |

Cloudflare Token **仅由管理员在登录后的“域名与 DNS”后台表单输入**，不写入源码或示例配置。应用将其加密保存到 `DATA_DIR/console.sqlite3`，不会回显；解密依赖原 `APP_SECRET`。最小权限与客户域名授权步骤见 [使用说明](docs/USAGE.md#cloudflare-连接与域名授权)。

不要提交 `.env`、持久数据、SQLite/WAL、`x-ui.db`、上传文件、备份、私钥、Token 或含客户信息的日志。提交前也应检查截图、测试输出和临时文件。备份网站数据库时同时妥善保存原密钥；仅有加密数据库不足以恢复集成功能。

## 部署

原生 systemd + nginx 配置、目录权限、HTTPS 和维护命令见 [部署维护文档](deploy/OPERATIONS.md)。部署前替换其中的示例站点地址，并保留既有业务服务。

Docker 方式：

1. 复制 `.env.example` 为 `.env`，设置自己的 `APP_SECRET`、`ALLOWED_HOSTS`，正式部署保持 `COOKIE_SECURE=true`。
2. 执行 `docker compose up -d --build`。
3. 执行 `docker compose exec console python -m app.cli create-admin site-admin`，交互创建管理员。
4. 在网站域名前配置 HTTPS 反向代理到 `127.0.0.1:8000`，可参考 [Caddy 示例](docs/Caddyfile)。

任务执行器仅允许单个 Uvicorn 进程。不要使用多个副本、`--workers 2` 或在远程安装期间热重载；同一目录的文件锁不能防止两台机器运行复制出来的同一任务队列。更新、迁移前先停止接收新任务并等待活动任务结束。

`/api/health` 检查网站存活并返回执行器状态；`/api/ready` 在执行器可接任务时返回 200，否则返回 503。运行中的任务在进程重启后会标为中断，不会盲目重复安装；排队任务则会自动领取。SQLite 使用 WAL，迁移或备份应使用一致快照，并核对数据库中上传文件的绝对路径，详见部署维护文档。

## 安装来源与业务边界

支持固定官方标签，对应手动命令为：

```bash
VERSION=v2.9.4 && bash <(curl -Ls "https://raw.githubusercontent.com/mhsanaei/3x-ui/$VERSION/install.sh") $VERSION
VERSION=v3.4.2 && bash <(curl -Ls "https://raw.githubusercontent.com/mhsanaei/3x-ui/$VERSION/install.sh") $VERSION
```

执行器让目标服务器下载固定标签的官方脚本，限制大小和超时，再检查固定 SHA-256。无人值守适配跳过安装后的交互配置并阻止配置前启动面板；脚本内容或结构不匹配时停止执行。

首版仅支持默认 `/etc/x-ui/x-ui.db`、同版本迁移，不支持 PostgreSQL、自定义数据库目录、跨版本升级/降级、通配符或 DNS-01 证书。面板证书与自动续期统一使用 `/root/cert/<域名>/fullchain.pem`、`privkey.pem`。迁移在重启前完成 HTTPS、服务与数据库检查，返回原端口和原路径组成的最终地址，再安排整机重启；不等待重启回连，也不将“已安排”表述为“重启后验收通过”。客户准备、迁移外部依赖与重试规则见 [使用说明](docs/USAGE.md)。

源码参考：[v2.9.4 安装脚本](https://github.com/mhsanaei/3x-ui/blob/v2.9.4/install.sh)、[v3.4.2 安装脚本](https://github.com/mhsanaei/3x-ui/blob/v3.4.2/install.sh)、[v3.4.2 数据库迁移](https://github.com/mhsanaei/3x-ui/blob/v3.4.2/internal/database/db.go)。

## 检查与限制

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q --basetemp=.test-tmp/all
node --check app/static/app.js
```

自动测试覆盖登录、CSRF、客户隔离、DNS 授权、上传、队列、失败重试、敏感信息清除、远程脚本与 SSH 流程模拟；测试不应操作真实客户服务器或生产 DNS。通过自动测试不代表所有 VPS 系统/架构、两版安装、真实证书签发和整机重启均已验收。正式使用前，在可重建测试 VPS 和测试域名上完成 [验收清单](docs/acceptance.md)，并核对节点和订阅的实际连通性。
