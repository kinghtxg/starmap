<div align="center">

# StarMap 星图

**内网资产测绘与账外资产发现引擎**

> 被动感知网内流量，自动测绘资产拓扑、登记主机资产、发现账外设备，对可疑行为**只打标签、不定性**。

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Offline](https://img.shields.io/badge/deploy-offline%20ready-2ea44f)]()
[![Single Binary](https://img.shields.io/badge/dist-single%20binary-7c3aed)]()

</div>

---

## 这是什么

StarMap 星图是一个部署在**内网**的资产测绘系统。它通过三路数据被动感知网络流量，自动生长出资产拓扑与主机台账，把"网络里到底有哪些设备、哪些是台账之外的影子设备"这一基本问题持续回答清楚。

核心价值是**账外资产发现**：企业在册资产台账之外，往往还散落着未登记的主机、测试机、旁路设备。StarMap 通过流量自动发现这些设备，与人工登记的资产台账对照，让"账实不符"一目了然。

## 设计原则

- **被动优先**：以流量发现为主（PCAP 导入 / 网卡抓包 / 远端探针上报），主动探测为辅。
- **只打标签，不定性**：对可疑行为仅产出特征标签（如"疑似 FRP 隧道特征"），不判定"违规/违法"，不告警外发，不联动封禁。
- **单二进制，离线可用**：纯 Go + SQLite（免 CGO），前端资源 `embed` 内嵌，无任何 CDN/外网依赖，内网一键部署。
- **不建权限体系**：不内置 RBAC；可外接 OIDC 身份源（如 APSSO）做可选的访问门卫，默认关闭。

## 功能特性

### 流量驱动的资产发现

- **三路数据接入**：PCAP/PCAPNG 离线导入、多网卡实时抓包（`-tags pcap`）、远端探针上报，统一汇入同一流水线。
- **拓扑自动测绘**：同 MAC 多 IP 合并、`/24` 子网聚合（可下钻）、公网按 `/24` 聚合为外部节点、边老化灰度、降噪、NAT 修复。
- **主机资产库**：自动发现的主机登记为**账外资产**，可人工归档登记归属单位 / 归属人 / 主机系统 / 位置；账外主机离线超时自动清理（默认 72h，可配）。
- **端口记录**：从流量五元组自动提取内网服务端口，也支持调用系统 `nmap` 做主动全端口扫描（默认 `1-65535`，可配），双来源汇总。

### 风险特征打标（仅标签）

| 规则 | 特征 | 等级 |
|---|---|---|
| `frp` | Go-TLS JA3/JA4 指纹 + 长连接保活 + 周期小包心跳（三中二 mid，三中三 high） | mid/high |
| `clash` | 随机高熵 SNI + 高频短间隔外联 + 持续陌生目的 | mid/high |
| `reverse_proxy` | 单内网 IP 映射 Host 数超阈值（默认 10） | mid |
| `unknown_egress` | 对外端口/链路数超 1h 滚动基线（带学习期） | mid |
| `multi_net` | 同节点/MAC/网关命中 ≥2 个网络域 | high |

### 可运营的闭环

- **复核闭环**：事件确认归档 / 误报自动加白 / 暂缓；白名单四维度（cidr/ip/host/node）命中即抑制。
- **网络域管理**：预置 gov/office/internet/prod 四域，CIDR 最长前缀匹配。
- **全量审计**：所有操作留痕（操作人 / 动作 / 对象），默认保留 90 天。
- **主动探测**：ARP / ICMP / Traceroute 跨平台（Linux + Windows），默认关闭。
- **可选认证**：本地账号或 OIDC 单点登录（APSSO），`auth.mode = none|local|oidc`，默认 `none`。

### 界面

自研设计系统（腾讯云规范风格、原生桌面质感、统一动效），标准网管拓扑图（设备图标 / 分层布局 / 正交折线 / 图例 / minimap / 右键菜单 / 导出 PNG·SVG / 双击下钻），操作按钮全站统一置于顶部工具栏。

## 架构

```
                ┌────────────────────── StarMap（单二进制）──────────────────────┐
 PCAP 文件 ──►  │  ingest/pcapfile ─┐                                            │
 网卡抓包 ──►  │  ingest/capture  ─┼─► parser.Aggregator ─► topology.Engine ─┐   │
 远端探针 ──►  │  ingest/probe    ─┘   (五元组/MAC/SNI/  (节点/边/聚合/老化)│   │
                │                       Host/JA3/JA4)                       ▼   │
                │                                        detect.Detector（周期评估）│
                │                                          │ RiskEvent          │
                │                                          ▼                    │
                │                          review（复核）+ audit（审计）+ assets │
                │                                          │                    │
                │                    store（SQLite，modernc 纯 Go 驱动）        │
                │  web/（embed.FS 内嵌）◄── api/server.go（Gin REST /api/*）     │
                └────────────────────────────────────────────────────────────────┘
```

技术栈：**Go 1.22+ · Gin · gopacket · modernc.org/sqlite（免 CGO）· 原生 HTML/CSS/JS（零构建、零 CDN）**。

## 快速开始

```bash
# 构建（纯 Go，无需 CGO）
CGO_ENABLED=0 go build -o starmap ./cmd/starmap

# 运行
./starmap -config configs/config.yaml
# 打开 http://127.0.0.1:8080

# 测试
go test ./...

# 生成合成 PCAP 测试数据（5 类场景 → testdata/out/）
go run testdata/gen_pcap.go

# 端到端验收（构建→起服务→上传 PCAP→断言事件/拓扑/复核/去重）
bash scripts/e2e.sh

# 全功能 API 冒烟测试（需先启动服务）
python3 scripts/smoke_test.py

# Linux 一键部署（systemd）
sudo bash scripts/deploy.sh
```

> 实时抓包需 `-tags pcap` 构建并安装 libpcap/npcap。主动端口扫描需系统安装 `nmap`。

## 数据接入示例

**PCAP 导入**（页面 `ingest.html` 上传，或）：

```bash
curl -F "file=@testdata/out/frp_tunnel.pcap" http://127.0.0.1:8080/api/ingest/pcap
```

**探针上报**：任意内网主机向 `POST /api/ingest/probe` 上报会话元数据，与抓包/PCAP 共用同一条流水线：

```json
{
  "probe_id": "probe-01",
  "ts": "2026-01-01T00:00:00Z",
  "flows": [{
    "src_ip": "10.1.2.3", "dst_ip": "10.1.2.4",
    "src_port": 40000, "dst_port": 443, "proto": "tcp",
    "bytes_up": 3000, "bytes_down": 8000,
    "sni": "www.example.com", "ja4": "t13d1516h2_..."
  }]
}
```

## 主要 API（`/api` 前缀）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` `/stats` | 健康检查 · 统计 |
| GET | `/topology` | 拓扑快照 |
| GET | `/topology/subnet/{cidr}` | 聚合子网下钻 |
| GET | `/assets` `/assets/stats` | 资产列表 · 资产统计 |
| POST/PUT/DELETE | `/assets/*` | 资产归档 / 维护 / 删除 |
| GET | `/ports` | 端口记录（流量 + 扫描双来源） |
| POST | `/ports/scan` | 主动端口扫描（nmap，异步） |
| GET | `/events` | 事件列表（状态/类型筛选） |
| POST | `/events/{id}/review` | 复核（confirm / false_positive / defer） |
| GET/POST/PUT/DELETE | `/whitelist` `/domains` | 白名单 · 网络域 CRUD |
| POST | `/ingest/pcap` `/ingest/probe` | PCAP 上传 · 探针上报 |
| POST | `/probe/trigger` | 主动探测（arp/icmp/traceroute） |
| GET/PUT | `/config` | 配置查询 / 热更新 |
| GET | `/audit` | 审计日志 |

## 截图

导入 `testdata/out/` 合成 PCAP 后的真实运行截图：

| 拓扑总览 | 主机资产 | 事件工作台 |
|---|---|---|
| ![topology](docs/screenshots/topology.png) | ![assets](docs/screenshots/assets.png) | ![events](docs/screenshots/events.png) |

| 数据接入 | 网络域 | 审计日志 |
|---|---|---|
| ![ingest](docs/screenshots/ingest.png) | ![domains](docs/screenshots/domains.png) | ![logs](docs/screenshots/logs.png) |

## 合规声明

- 对所有命中规则的流量**只打标签，不作定性结论**，不发送告警通知，不联动封禁。
- **不解密**任何加密流量：仅解析 TLS ClientHello 明文元数据（SNI / 密码套件 / 扩展）用于 JA3/JA4 指纹。
- 不内置漏洞扫描、IDS 规则匹配或攻击载荷；主动探测默认关闭，需显式开启。
- **请仅在获得授权的网络环境中使用。**

> JA4 指纹为按公开算法规范（FoxIO 的 JA4 方法学字符串格式）的自研实现，仅复用其指纹字符串结构，不使用其许可证约束的数据文件或代码，与 Apache-2.0 兼容。

## 文档

- [SPEC](SPEC.md) — 需求与数据模型规格
- [CHANGELOG](CHANGELOG.md) — 版本变更
- [docs/AUTH-APSSO.md](docs/AUTH-APSSO.md) — 账号系统与 APSSO SSO 接入指南
- [docs/PM-DATA-INGEST-V2-DESIGN.md](docs/PM-DATA-INGEST-V2-DESIGN.md) — 数据接入 v2 产品设计

## 许可证

[Apache License 2.0](LICENSE) · © 极客星空安全实验室
