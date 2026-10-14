# StarMap 星图 · 网内拓扑自动测绘引擎 V1.0

> 极客星空实验室出品 · Apache-2.0
> 纯 Web B/S 架构。被动感知网内流量，自动测绘资产拓扑，对可疑行为**只打标签、不定性**。

## 功能特性

- **网内拓扑自动测绘**：PCAP 文件导入 / 网卡实时抓包 / 远端探针上报三路数据接入，自动生长节点与链路，同 MAC 多 IP 合并、/24 子网聚合（可下钻）、公网按 /24 聚合为外部节点、边老化灰度、降噪、NAT 修复。
- **风险打标（四+一类规则，仅标签不定性）**：
  - `frp`：Go-TLS JA3/JA4 指纹 + >1h 保活长连接 + 周期小包心跳，三中二 mid、三中三 high；
  - `clash`：随机高熵 SNI + 高频短间隔公网外联 + 持续陌生目的；
  - `reverse_proxy`：单内网 IP 映射 Host 数超阈值（默认 10，可配）；
  - `unknown_egress`：对外服务端口/链路数超 1h 滚动基线（max(3×基线, 20)，启动后 10min 学习期）；
  - `multi_net`：同节点/同 MAC/同首跳网关 MAC 命中 ≥2 个网络域 → high。
- **复核闭环**：事件确认归档 / 误报自动加白 / 暂缓；白名单四种维度（cidr/ip/host/node）命中即抑制，已有 pending 事件自动转误报；全量操作审计留痕（默认保留 90 天）。
- **网络域管理**：预置 gov/office/internet/prod 四域，CIDR 最长前缀匹配，CRUD 后节点归属即时重算。
- **事件去重**：同 (type, node) 且 24h 内已有 pending/confirmed 事件 → 仅更新证据不重复建单（§10.5）。
- **合规红线**：不做登录/RBAC（仅留 middleware 接口位）、不解密流量、不漏洞扫描、无 IDS 告警外发。

## 架构

```
                 ┌──────────────────────── StarMap (单二进制) ────────────────────────┐
  PCAP 文件 ──►  │ ingest/pcapfile ─┐                                                 │
  网卡抓包 ──►  │ ingest/capture  ─┼─► parser.Aggregator ─► topology.Engine ─┐        │
  远端探针 ──►  │ ingest/probe    ─┘   (五元组/MAC/TTL/    (节点/边/聚合/老化)│        │
                 │                          SNI/Host/JA3/JA4)                 ▼        │
                 │                                              detect.Detector (周期评估)│
                 │                                                │ RiskEvent          │
                 │                                                ▼                    │
                 │                                  review（确认/误报加白/暂缓）+ audit │
                 │                                                │                    │
                 │                                  store (SQLite, modernc 纯 Go 驱动)  │
                 │  web/ (embed.FS 内嵌) ◄── api/server.go (Gin REST /api/*)            │
                 └──────────────────────────────────────────────────────────────────────┘
```

技术栈：Go 1.22 + Gin + gopacket + modernc.org/sqlite（免 CGO）+ 前端静态页（Tailwind CDN + Cytoscape.js CDN）。

## 快速开始

```bash
# 构建（纯 Go，无需 CGO）
CGO_ENABLED=0 go build -o starmap ./cmd/starmap

# 运行（缺配置文件时用内置默认值）
./starmap -config configs/config.yaml
# 打开 http://127.0.0.1:8080

# 测试
go test ./...

# 生成合成 PCAP 测试数据（5 类场景 → testdata/out/）
go run testdata/gen_pcap.go

# 端到端验收（构建→起服务→上传 5 个 PCAP→断言事件/拓扑/复核/去重）
bash scripts/e2e.sh

# Linux 一键部署（systemd）
sudo bash scripts/deploy.sh
```

Docker（可选）：单二进制 + embed 静态资源，任意最小镜像即可运行，例如
`FROM gcr.io/distroless/static-debian12` + `COPY starmap /starmap` + `ENTRYPOINT ["/starmap"]`。
实时抓包需 `-tags pcap` 构建并安装 libpcap，且容器需要 `NET_ADMIN/NET_RAW` 能力。

## API 摘要（/api 前缀，JSON）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/health · /api/stats | 健康检查 · 统计 |
| GET | /api/topology | 拓扑快照（Nodes/Edges/Stats/GeneratedAt） |
| GET | /api/topology/subnet/{cidr} | 聚合子网下钻 |
| GET | /api/nodes/{id} | 节点详情（含对端） |
| GET | /api/events?status=&type= | 事件列表（组合筛选） |
| POST | /api/events/{id}/review | 复核 `{action: confirm\|false_positive\|defer, note, reviewer}` |
| GET/POST/PUT/DELETE | /api/whitelist | 白名单 CRUD（kind: cidr/ip/host/node） |
| GET/POST/PUT/DELETE | /api/domains | 网络域 CRUD |
| POST | /api/ingest/pcap | PCAP/PCAPNG multipart 上传（≤200MB） |
| POST | /api/ingest/probe | 探针上报 `{probe_id, token?, flows:[...], ts}` |
| POST | /api/capture/start · /stop，GET /status | 抓包控制 |
| GET/PUT | /api/config | 配置查询/热更新（持久化） |
| GET | /api/audit | 审计日志 |
| POST | /api/probe/trigger | 主动探测 `{type: arp\|icmp\|traceroute, target}`（默认关闭） |

## PCAP 导入与探针接入

**PCAP 导入**：页面 ingest.html 上传，或
`curl -F "file=@testdata/out/frp_tunnel.pcap" http://127.0.0.1:8080/api/ingest/pcap`。
支持经典 PCAP 与 PCAPNG；超过 200MB 或损坏文件返回 4xx。上传后同步完成拓扑生长与一轮检测评估。

**探针接入**：任意内网主机向 `POST /api/ingest/probe` 上报 JSON：

```json
{
  "probe_id": "probe-01",
  "token": "可选，配置 probe_token 后必填（也可用 X-Probe-Token 头）",
  "ts": "2025-03-01T00:00:00Z",
  "flows": [{
    "src_ip": "10.1.2.3", "dst_ip": "10.1.2.4",
    "src_port": 40000, "dst_port": 443, "proto": "tcp",
    "bytes_up": 3000, "bytes_down": 8000, "packets": 40,
    "first_seen": "2025-03-01T00:00:00Z", "last_seen": "2025-03-01T00:00:30Z",
    "sni": "www.example.com"
  }]
}
```

探针与抓包/PCAP 共用同一条 PacketSource → parser → topology 流水线。
**风险提示**：探针上报默认无鉴权，生产环境请配置 `probe_token` 并置于可信网段。

## 合规声明

- 本系统对所有命中规则的流量**只打标签（label），不作任何定性结论**，不发送告警通知，不联动封禁。
- **不解密**任何加密流量：仅解析 TLS ClientHello 明文元数据（SNI/密码套件/扩展）用于 JA3/JA4 指纹。
- 不内置漏洞扫描、IDS 规则匹配或攻击载荷；主动探测（ARP/ICMP/Traceroute）默认关闭，需显式开启。
- 请仅在获得授权的网络环境中使用。

## JA4 说明

JA4 指纹为**按公开算法规范（FoxIO 公开的 JA4 方法学字符串格式）自研实现**：
仅复用其指纹字符串结构（`t13d1516h2_..._...`），不使用任何 FoxIO SAL 许可证约束的数据文件或代码，
与项目 Apache-2.0 许可兼容。JA3 同理为公开算法（MD5 五段式）的独立实现，指纹表为社区公开观测值的自维护子集。

## 截图

以下为导入 `testdata/out/` 合成 PCAP 后的真实运行截图（可用 `scripts/shot.py` 重新生成）：

| 页面 | 截图 |
|---|---|
| 拓扑总览 | ![topology](docs/screenshots/topology.png) |
| 事件工作台 | ![events](docs/screenshots/events.png) |
| 数据接入 | ![ingest](docs/screenshots/ingest.png) |
| 网络域 | ![domains](docs/screenshots/domains.png) |
| 白名单 | ![whitelist](docs/screenshots/whitelist.png) |
| 审计日志 | ![logs](docs/screenshots/logs.png) |

产品审查报告见 [docs/PM-REVIEW-2026-10-14.md](docs/PM-REVIEW-2026-10-14.md)（P0/P1/P2 分级整改清单）。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE)。© 极客星空实验室。
