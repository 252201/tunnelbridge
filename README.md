# TunnelBridge

TunnelBridge 是一套面向个人开发者的自托管 TCP 内网穿透工具。Mac 客户端只建立出站 HTTPS/WSS 连接，公网中继收到 TCP 连接后，通过短期一次性票据为该连接建立独立数据通道。

## 功能

- Rust/Axum 公网中继、SQLite 持久化和动态 TCP 端口监听。
- Tauri 2 macOS 客户端，令牌存入 macOS Keychain，关闭窗口后继续在菜单栏运行。
- TCP 映射、IPv4/IPv6 CIDR 白名单、显式公开访问和局域网目标确认。
- 单管理员 Web 控制台、设备令牌、隧道状态、活动连接、指标和审计记录。
- Docker Compose + Caddy 自动 HTTPS，GHCR 多架构镜像发布配置。
- Universal macOS DMG、Developer ID 公证和 Tauri 签名更新工作流。

## 仓库结构

```text
crates/protocol       Rust 共享协议和 API 类型
server                Axum/SQLite 中继服务
desktop/src-tauri     Tauri Rust 客户端和隧道代理
web/desktop           macOS 客户端界面
web/admin             服务端管理界面
packages/api-types    两个前端共享的 TypeScript 类型
docker                Caddy 配置
```

## 本地开发

要求 Rust 1.94+、Node.js 24+、pnpm 11+，macOS 客户端要求 macOS 13+。

```bash
pnpm install
pnpm build:web

mkdir -p data
TB_ADMIN_PASSWORD='change-this-development-password' \
TB_SECURE_COOKIES=false \
TB_DATABASE_URL='sqlite://data/tunnelbridge.db?mode=rwc' \
cargo run -p tunnelbridge-server
```

管理后台默认位于 [http://127.0.0.1:8080](http://127.0.0.1:8080)，用户名固定为 `admin`。本地 HTTP 开发必须将 `TB_SECURE_COOKIES=false`，生产环境不可关闭 Secure Cookie。

另开终端启动桌面应用：

```bash
pnpm dlx @tauri-apps/cli@latest dev --config desktop/src-tauri/tauri.conf.json
```

在管理后台的“设备与令牌”页创建设备，把只展示一次的令牌粘贴到 Mac 客户端，然后创建 TCP 隧道。

## VPS 部署

1. 将域名 A/AAAA 记录指向 VPS，并在防火墙放行 `80`、`443` 和配置的 TCP 映射端口范围。
2. 复制环境变量并设置强密码：

```bash
cp .env.example .env
docker compose up -d --build
```

3. 打开 `https://$TB_DOMAIN`，使用 `admin` 和 `TB_ADMIN_PASSWORD` 登录。
4. 首次初始化后，密码哈希已写入 SQLite；可从运行环境移除 `TB_ADMIN_PASSWORD`。删除数据卷会重新触发首次初始化。

Caddy 负责管理后台、REST API 和 WebSocket 的 TLS。映射端口由中继容器直接监听，因此云安全组和宿主机防火墙必须同时放行对应范围。

## 安全模型

- 新隧道默认要求至少一个 CIDR；选择公开访问必须在客户端显式确认。
- 非回环本地目标必须显式允许，以避免无意暴露局域网服务。
- 设备令牌为高熵随机值，服务端仅保存 BLAKE3 哈希；桌面端仅保存在 Keychain。
- 管理密码使用 Argon2id；管理会话使用 HttpOnly、Secure、SameSite=Strict Cookie 和 CSRF Token。
- 每个 TCP 会话使用 15 秒有效、一次消费的数据票据。票据和设备令牌不会写入应用日志。
- TunnelBridge 不检查或记录转发载荷。SSH、数据库等目标协议仍应启用自身身份认证和加密。

生产环境应定期备份 `tunnelbridge-data` 卷，并用主机防火墙再次约束映射端口来源。撤销设备后，已有控制连接会被断开，新数据通道将无法通过认证。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TB_LISTEN_ADDR` | `0.0.0.0:8080` | 管理/API 服务监听地址 |
| `TB_DATABASE_URL` | `sqlite://data/tunnelbridge.db?mode=rwc` | SQLite 地址 |
| `TB_ADMIN_PASSWORD` | 无 | 首次启动必填，至少 12 字符 |
| `TB_PORT_START` / `TB_PORT_END` | `20000` / `20100` | 公网 TCP 端口池 |
| `TB_TICKET_TTL_SECONDS` | `15` | 数据票据有效期 |
| `TB_CONNECT_TIMEOUT_SECONDS` | `15` | 等待代理数据通道时间 |
| `TB_IDLE_TIMEOUT_SECONDS` | `600` | 单连接空闲超时 |
| `TB_SESSION_TTL_SECONDS` | `43200` | 管理会话有效期 |
| `TB_AUDIT_RETENTION_DAYS` | `30` | 审计日志保留天数 |
| `TB_SECURE_COOKIES` | `true` | 仅本地 HTTP 开发可关闭 |

## 发布准备

在正式发布前必须完成两项一次性配置：

1. 将 `desktop/src-tauri/tauri.conf.json` 中的更新地址替换成真实 GitHub 仓库，并写入由 `tauri signer generate` 创建的公钥。
2. 在 GitHub Actions Secrets 中配置：
   `APPLE_CERTIFICATE`、`APPLE_CERTIFICATE_PASSWORD`、`APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_PASSWORD`、`APPLE_TEAM_ID`、`TAURI_SIGNING_PRIVATE_KEY`、`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`。

Apple 证书使用 base64 编码的 `.p12` 内容。Tauri 私钥必须与配置中的公钥匹配，且绝不能提交到仓库。

## 验证

```bash
cargo fmt --all --check
cargo clippy -p tunnelbridge-protocol -p tunnelbridge-server --all-targets -- -D warnings
cargo test -p tunnelbridge-protocol -p tunnelbridge-server
pnpm typecheck
pnpm build:web
```

当前首版只支持 TCP。UDP、HTTP 域名路由、P2P 打洞、多管理员、计费和其他桌面平台不在范围内。
