# TunnelBridge 更新日志

本文件记录每个已发布版本的主要变化。版本标题与 Git tag 保持一致，GitHub Actions 会在发布时自动提取对应章节作为 Release 说明。

## [v0.2.2] - 2026-08-18

### 修复

- 修复桌面端公网地址过长时与访问策略标签重叠的问题；完整地址可通过悬停提示查看。
- 修复 macOS WebView 中删除隧道确认框不显示导致删除按钮无响应的问题。
- 删除隧道时增加应用内确认、删除中状态、错误提示和成功反馈。

## [v0.2.1] - 2026-08-18

### 修复

- 显式初始化 Rustls `ring` 加密提供程序，修复 KCP/TLS 承载启动时可能出现的运行时 panic。
- 改进 Caddy 接管已有 Nginx 的流程，兼容 SysV init 服务并确认 80/443 端口已释放后再启动 Caddy。
- 发布服务端和 macOS 客户端的 v0.2.1 修复版本。

## [v0.2.0] - 2026-08-18

### 新功能

- 协议 v2 承载层支持 QUIC、KCP/TLS 和持久 WSS，并支持 QUIC 优先、WSS 回退。
- TCP 连接改为单条持久承载中的多路复用逻辑流。
- 增加 UDP 代理、UDP 会话与数据报分片/重组限制。
- 增加 Web 代理，支持本地 HTTP/HTTPS、HTTPS 公网入口、HTTP 自动跳转和动态子域名证书。
- 增加承载证书、SPKI 指纹固定、能力协商和传输状态显示。
- 管理 API、共享协议类型、SQLite 隧道模型和客户端创建流程同步升级到 v2。
- 公网连接事件增加来源国家信息；服务端镜像支持 amd64 与原生 ARM64 构建。

### 升级注意

- v2 直接替换 v1 数据通道，升级时请同时更新客户端和服务端。

## [v0.1.1] - 2026-08-17

### 新功能

- 增加交互式 VPS 一键部署脚本，支持 GHCR、Cloudflare DNS、Caddy/Nginx、SQLite 备份和管理员密码初始化。
- 增加菜单栏在线、连接中、离线和错误状态颜色提示。
- 更新 TunnelBridge 应用图标及管理后台、桌面端站点图标。
- 发布流程加入 BuildKit GitHub Actions 缓存，减少重复构建时间。

## [v0.1.0] - 2026-08-17

### 首次发布

- 发布 TunnelBridge 首个 macOS Universal DMG，支持 Apple Silicon 与 Intel。
- 提供 TCP 内网穿透、CIDR 白名单、设备令牌、管理员后台和菜单栏常驻能力。
- 启用 Tauri 更新签名和 GitHub Releases 自动更新资产。
