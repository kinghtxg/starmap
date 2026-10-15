# Changelog

## V1.3 (2026-10-15)

### 新增
- **探针位置自动归纳拓扑**：探针上报携带 `location` 位置字段，服务端维护探针注册表（`/api/probes`），探针发现的节点自动归属位置，拓扑图按位置分组为泳道（同一位置归一组，组间垂直堆叠，泳道标签「位置 · 层级」）。

## V1.2 (2026-10-15)

### 新增
- **主机资产库**（`/api/assets`）：流量自动发现的主机登记为「账外资产」，可归档登记归属信息（归属单位 / 归属人 / 主机系统 / 位置 / 备注）；未归档主机离线超阈值（默认 72h，可配）自动从拓扑与资产库清理；归档主机超时动态判离线。
- **端口记录**（`/api/ports`）：双来源——流量五元组自动提取内网服务端口 + 调用系统 `nmap` 主动全端口扫描（默认 `1-65535`，异步后台，可配速率）。

### 修复
- **探针 TLS 指纹贯通**：修复探针 flows 合成报文时 SNI/JA3/JA4 被丢弃的问题，`frp`/`clash`/`reverse_proxy` 规则对探针数据恢复生效。
- **主动探测跨平台**：ICMP/ARP/Traceroute 适配 Windows（此前仅 Linux 写法，`ping -c`/`/proc/net/arp` 在 Windows 全失效）。
- **ICMP 探测支持 CIDR 网段**：此前 `/24` 报「无法解析」。
- **未匹配 API 返回 JSON 404**：此前走 SPA 兜底返回 HTML，导致前端 `JSON.parse` 报 `Unexpected token '<'`。

## V1.1 (2026-10-15)

### 新增
- **标准拓扑图 UI**（`web/assets/topo.js`）：自绘 SVG 拓扑引擎。标准网络设备图标（路由器/交换机/防火墙/服务器/终端/云/子网）、分层布局、正交折线连线、风险三色描边、告警徽标、图例、minimap 缩略图、缩放工具栏、框选、右键菜单、hover tooltip、导出 PNG/SVG、双击聚合节点下钻、空态引导、大图标签隐藏。
- **设计系统**（`web/assets/theme.css`）：腾讯云规范风格设计令牌与组件库（按钮/输入/表格/卡片/模态/开关/徽标/toast/空态），统一动效曲线，操作按钮全站统一置于顶部工具栏，尊重 `prefers-reduced-motion`。
- **共享前端工具**（`web/assets/app.js`）：事件委托绑定（消除内联 onclick 存储型 XSS）、toast、模态、分页、数字滚动动画、统一导航框架。
- **账号系统 + APSSO SSO**（`internal/auth/`，默认关闭）：`auth.mode = none | local | oidc` 三模；本地账号 bcrypt；OIDC 走 authorization_code + PKCE + state；HMAC 签名 HttpOnly 会话 Cookie；`web/login.html` 登录页；`scripts/deploy-apsso.sh` 一键部署（支持 `--no-sso`）；仅「已认证/未认证」两态，不做 RBAC（合规裁定 K1/K2/K3，见 `docs/AUTH-APSSO.md`）。
- **CORS 白名单**：新增 `cors_origins` 配置，默认空 = 仅同源。

### 修复（P0 整改，对应 docs/PM-REVIEW-2026-10-14.md）
- **P0-1** `Detector.Evaluate` 并发评估导致 `fatal error: concurrent map writes` 进程自杀 → 全轮串行化（`sync.Mutex`）。
- **P0-2** 拓扑节点/边不落库、重启失忆、白名单 `node:<id>` 跨重启错配静默误抑制 → 稳定 NodeKey（`mac:` 优先 / `ip:` 兜底 / `ext:` 外部聚合）+ 在线迁移回填 + 批量幂等 upsert + 启动恢复重建索引 + 2s 节流 flush；白名单 node 维度改 NodeKey 并向后兼容旧数字格式。
- **P0-3** 保存配置静默清空 `probe_token` → 后端忽略空串（前端本就留空不下发，双保险）。
- **P0-4** 无鉴权暴露面 → 默认监听改 `127.0.0.1:8080`、CORS 收紧为白名单、审计 Actor 由硬编码 `api` 改为登录身份或 ClientIP。

### 变更
- 前端移除 Tailwind CDN / Cytoscape / jsPDF 全部外网依赖（内网离线可用），`web/assets/layout.js` 由 `app.js` 取代。
- 配置新增 `cors_origins` 与 `auth` 节；`configs/config.yaml` 默认监听改为 `127.0.0.1:8080`。
- `docs/PM-DATA-INGEST-V2-DESIGN.md`：数据接入 v2 产品设计文档（PM agent 产出，含新发现的探针 TLS 指纹丢失 P0 与 V1.2 排期）。

### 已知限制
- 实时抓包需 `-tags pcap` 构建 + libpcap/npcap + CAP_NET_RAW（页面已有明确提示）。
- 探针上报的 SNI/JA3/JA4 字段在服务端合成报文时被丢弃，frp/clash/reverse_proxy 三规则对探针数据暂不生效（见 PM-DATA-INGEST-V2-DESIGN.md §1.4.3，V1.2 修复）。
- `go test -race` 在 Windows 无 CGO 环境不可用，并发回归由串行化设计 + 单测覆盖。

## V1.0 (2026-10-14)

- 首发版本：三路数据接入、/24 聚合下钻、同 MAC 多 IP 合并、边老化灰度、降噪、NAT 修复、JA3/JA4 指纹、五类风险打标、复核闭环、白名单抑制、网络域管理、全量审计、8 页面 Web 控制台。
