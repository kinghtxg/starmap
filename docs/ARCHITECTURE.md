# StarMap 架构与实现详解

> 面向两类读者：**要接手二开的工程师**（想知道某功能落在哪个文件、为什么这么写），
> **要做安全评估的人**（想知道信任边界在哪、哪些地方刻意不做）。
>
> 版本：1.2.0 · 更新于 2026-10-27
> 配套文档：[部署运维手册](OPERATIONS.md) · [安全模型](SECURITY.md) · [发布说明](RELEASE-1.2.md)

---

## 0. 这份文档怎么读

- 想快速跑起来 → 直接看 [OPERATIONS.md](OPERATIONS.md) 的「五分钟部署」。
- 想知道某功能怎么实现 → 第 3–6 章按功能分节，每节都有「代码位置」。
- 想改代码 → 第 13 章是文件地图，第 14 章是「加一条规则 / 加一个页面」的具体步骤。
- 做安全评估 → 第 8 章（API 层）与 [SECURITY.md](SECURITY.md)。

全篇约定：**「为什么」比「是什么」重要**。这个项目里几乎每个反直觉的写法，
背后都对应一次真实踩坑（CI 抓到的竞态、真实网络里才暴露的 OOM、某次误判）。
这些理由写在代码注释里，本文把它们汇总。

---

## 1. 产品定位与边界

### 1.1 一句话

部署在内网的**被动资产测绘 + 账外资产发现**引擎：从流量里自动长出资产拓扑，
和人工台账做三方对照，把"网里有、账上没有"的设备找出来。

### 1.2 明确不做什么

| 不做 | 原因 |
|---|---|
| 不解密流量 | 合规红线。只解析明文 HTTP 头、TLS 握手的 SNI/证书指纹 |
| 不告警外发 / 不联动封禁 | 只产出**标签**与**待处置事件**，处置动作由人确认 |
| 不定性为"违规" | 一机两网是监管红线，但系统只标注特征，不代替人下结论 |
| 不做目录爆破 / 漏洞扫描 | 属渗透测试动作，超出"资产测绘"的授权范围 |
| 不自建账号与权限体系（可选） | 默认零配置无认证；需要时接本地账号或 OIDC 单点登录 |

### 1.3 为什么"被动"是主路径

政务网 / 隔离内网的现实约束：

1. 大面积 ICMP 被屏蔽，ARP 只在本广播域有效；
2. 运维机上常常装不上 masscan / nmap；
3. 主动扫描会在目标侧留下大量连接记录，授权风险高于"镜像流量看一眼"。

所以主路径是**被动**（镜像流量 / 探针上报），主动发现（1.2 起）是**可选补充**，
且默认关闭、独立授权。

---

## 2. 总体架构

单二进制，无外部依赖（SQLite 用 pure-Go 驱动，前端 `embed.FS` 内嵌）。

```
┌──────────────────────────── StarMap 单进程 ────────────────────────────┐
│                                                                        │
│  数据接入                      分析内核                    对外         │
│  ─────────                    ─────────                   ─────        │
│  ingest/pcapfile ─┐           parser.Aggregator ─┐        api (Gin)    │
│  ingest/capture  ─┼─► 报文 ─► (会话/五元组/MAC/  ├─► topology.Engine   │
│  ingest/probe    ─┘           SNI/JA3/JA4/XFF)   │   (节点/边/聚合)    │
│                                                  │         │           │
│                                                  │         ▼           │
│                                   detect.Detector（每 2s 评估）         │
│                                                  │  RiskEvent          │
│                                                  ▼                     │
│                                   review（复核）+ audit（审计留痕）     │
│                                                                        │
│  probe.Scanner ──► 主动发现（1.2）──► ports / assets 表                 │
│                                                                        │
│  store（SQLite · modernc 纯 Go · WAL · 单连接）                        │
│  web/（embed.FS 内嵌，零构建零 CDN）                                    │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 一次数据流转的完整路径

以"探针上报一个 frp 隧道会话"为例：

1. **HTTP 入口**：`POST /api/ingest/probe`（`internal/api/server.go: ingestProbe`）
   - 请求体上限 64MB（`MaxBytesReader`），超限 413
   - 若配了 `probe_token`：header / query / body 三处取，`constant-time` 比较
2. **合成为报文**：`probeFlow` → `parser.PacketInfo`（补齐 SNI/JA3/JA4，1.2 前这里曾丢字段）
3. **聚合**：`parser.Aggregator.Ingest` → 会话表（增量、有容量上限）
4. **抽取**：引擎每 2s 调 `Aggregator.Finalize()` 拿**有变化的**会话（不是全表）
5. **建图**：`topology.Engine.Ingest(session)` → 节点（同 MAC 合并）+ 边（流量/归属）
6. **检测**：`detect.Detector.Evaluate()` 跑五类规则 → 命中则建 `RiskEvent`（pending）
7. **入库**：事件落 `events` 表；拓扑按 `dirty` 集合节流 flush 到 `nodes`/`edges`
8. **呈现**：前端 `index.html` 拉 `/api/topology`，`events.html` 拉 `/api/events`

---

## 3. 数据接入

### 3.1 PCAP 文件导入

**代码**：`internal/api/server.go: ingestPCAP` → `internal/ingest/pcapfile.go`

- 上限 200MB（`MaxPCAPUpload`），先查 `Content-Length` 再 `MaxBytesReader` 双保险。
- 用 gopacket 流式读，逐包 `parser.ParsePacket`，不把整包读进内存。
- 支持 `.pcap` / `.pcapng`；解析失败的行不会中断整批，只累加错误计数。
- **去重语义**：同一文件重复上传靠事件去重（24h 窗口）与端口 upsert 天然幂等，
  重复上传不会让事件翻倍。

**边界**：不做 TCP 流重组。只从单个报文里取五元组、MAC、TLS ClientHello、HTTP 头。
重组需要缓存大量流状态，对"资产清单"这个目标收益很低。

### 3.2 实时抓包

**代码**：`internal/ingest/capture.go`（`-tags pcap` 构建）

- 依赖 libpcap/npcap + 网卡权限；未编译该 tag 时页面显示"当前平台未编译 libpcap 支持"，
  不会静默失败。
- 多网卡可配（`capture_interfaces`），BPF 表达式透传（`capture_bpf`）。
- 启停通过 `POST /api/capture/{start,stop}`，状态查 `/api/capture/status`。

### 3.3 探针上报

**代码**：`internal/api/server.go: ingestProbe`

请求体（节选）：

```json
{
  "probe_id": "probe-gov-internal",
  "location": "政务内网-核心段",
  "token": "...",
  "flows": [{
    "src_ip": "10.10.1.50", "dst_ip": "104.21.33.5",
    "src_port": 51234, "dst_port": 443, "proto": "tcp",
    "mac": "02:00:de:ad:01:01",
    "bytes_up": 2048, "bytes_down": 512, "packets": 12,
    "sni": "random-8f2a.example.com", "ja3": "cd08e31494f9531f560d64c695473da9",
    "ja4": "t13d1516h2_...", "location": "政务内网-核心段"
  }]
}
```

**校验顺序**（顺序本身是设计的一部分）：

1. 体积（64MB）→ 2. token → 3. `probe_id` 必填 → 4. `packets` 与 `flows` 不能同时为空。

**位置继承**：`report.location` → `metadata.location` → 每条 flow 自己的 `location`。
位置最终变成拓扑的泳道分组与资产的初始 `location`。

**为什么探针要带 MAC**：没有 MAC 时只能按 IP 建节点，DHCP 换址会产生"幽灵设备"。
MAC 是唯一能把"同一台机器换了地址"认出来的锚点。

### 3.4 解析层

**代码**：`internal/parser/`

| 能力 | 实现 | 关键点 |
|---|---|---|
| 五元组 + 方向 | `ParsePacket` | 双向会话归一到同一 `Session` |
| MAC | 以太网头 | 无 MAC（探针 flow）时留空，节点用 IP 做 key |
| TLS ClientHello | `ParseClientHello` | 手写解析，不引入完整 TLS 库；只取 SNI/cipher/extension |
| JA3 / JA4 | `ja3.go` / `ja4.go` | 自实现，含 GREASE 剔除；JA4 按 `transport+version+SNI+cipher数+ALPN` 拼 |
| HTTP Host | `ExtractHTTPHost` | 只在 payload 前缀像 HTTP 时解析 |
| X-Forwarded-For | `forwarded.go` | 支持 XFF / X-Real-IP / RFC7239 `Forwarded` / `Via`；**8 跳 / 32KB 上限** |

**有心跳降噪**：短连接 + 小包 + 低字节数的会话不进拓扑（`noise_*` 三个阈值），
否则 DNS/健康检查会把图塞满无意义的小边。

---

## 4. 聚合与拓扑

**代码**：`internal/parser/aggregator.go`（会话）、`internal/topology/engine.go`（图）

### 4.1 会话聚合与内存回收

被动分析面对的是持续输入，**"只进不出"是这类产品的结构性缺陷**：
会话表无回收 + 每轮把全表重放给引擎，在开发机跑几分钟没事，真实网络几小时就是 OOM。

1.0 起的三层治理：

| 机制 | 默认值 | 作用 |
|---|---|---|
| 增量下发 | — | `Finalize()` 只返回自上次抽取后有变化的会话，引擎侧开销从 O(全表) 降到 O(变更) |
| 三类回收 | 30s / 300s / 6h | FIN-RST 后静默 30s、任意会话静默 300s、存活超 6h |
| 容量硬上限 | 200000 | 打满先回收再丢弃，丢弃计数进 metric |

⚠️ **回收判定用"摄入墙钟"而不是报文时间戳**。导入历史 PCAP 时，
报文时间戳可能是几个月前，用它判定会把整批会话在第一轮就当成"静默超时"清空。

⚠️ `Finalize()` 改增量后，检测规则里若需要"跨会话全表统计"，
必须显式改用 `Sessions()` 全表接口，否则规则会静默失效（1.0 踩过）。

### 4.2 节点识别：同 MAC 多 IP 合并

`nodeForLocked` 的优先级：

1. 有 MAC → 用 `mac:<mac>` 作为 `NodeKey`
2. 无 MAC → `ip:<ip>`
3. 外部地址 → `ext:<cidr>`

同一 MAC 出现新 IP 时，把 IP 追加到节点的 `IPs`，**不新建节点**。
这是"一机两网"能被识别的前提：一台设备跨两个 /24 时，是一个节点带两个 IP。

### 4.3 /24 聚合与下钻

- 单个内网 /24 的成员数 ≥ `aggregate_threshold`（默认 20）时，
  在**全网视图**里折叠成一个聚合节点（`subnet:10.10.1.0/24`）。
- 双击聚合节点下钻 → `GET /api/topology/subnet/{cidr}`：
  - 成员节点用**自身真实 ID**（不是聚合 ID）——早期版本在这里把成员映射成聚合 ID，
    导致网段内链路两端同源、整条边被前端丢弃，下钻只能看到一堆孤立圆点（1.6 的 P1）。
  - 补齐"上下文节点"：指向其它网段/外部的边，其外部端点补成灰色节点，
    否则跨网归属与出口方向在下钻视图里看不见。

### 4.4 风险锚点：异常不被聚合吞掉

中/高风险节点**不参与 /24 聚合**，始终以自身身份出现在全网视图（红色虚环 + "异常"副标签）。

理由：/24 一旦折叠，网段里那台"一机两网"或"跑隧道"的设备就被聚合节点吞了——
恰恰藏起了最该被看见的东西。**"异常在大网里被聚合吞掉"是这类产品的通病**，
这是本项目的差异化点。

### 4.5 网段归属边（`Kind=owner`）

按设备自身 IP 的 /24 归属推导的虚线关联，**无流量也会画**。

解决的问题：一台双归属设备，第二个网段只访问外网时，图上完全看不出它属于那个网段。
现在双归属主机会同时连到两个网段聚合节点，拓扑本身就是跨网证据。
与已有流量边共用端点时不重复生成。

### 4.6 XFF 七层转发还原

**代码**：`internal/parser/forwarded.go` + `engine.go: applyForwardedLocked`

请求经过 nginx / SLB / API 网关后，被动侧只能看到代理 IP。
后果是"一台代理"被当成"一台设备"，代理背后几十台客户端完全不可见。

处理：

1. 从 HTTP 头解析转发链（XFF 链序保留，`XFF[0]` 是最原始客户端）。
2. 内网客户端 → 独立节点（标签 `xff-client`）+ 一条 `proto=xff` 关系边。
3. 转发节点打 `xff-proxy` 标签，**且不参与聚合**（否则"代理 + 背后一片客户端"一起被折叠）。
4. 检测规则 `xff_spoof`：XFF 首跳等于观测源、或 `X-Real-IP` 与 XFF 首跳矛盾 → 打 mid 标签。

⚠️ **XFF 是客户端可写文本**。8 跳 / 32KB 上限是硬约束，构造超长链能拖慢解析并撑爆内存。

### 4.7 边老化与持久化

- 边老化：`aging_seconds`（默认 86400）内无流量的边移除。
- 节点/边按 `dirty` 集合节流落库（2s 一批），不是每次变更都写。
- 启动时 `restoreLocked` 从 `nodes`/`edges` 表重建索引，
  并给缺失 `node_key` 的老数据在线回填（1.1 的 P0-2）。

---

## 5. 检测与复核

**代码**：`internal/detect/`

### 5.1 五类规则

| 类型 | 判定要点 | 风险 |
|---|---|---|
| `multi_net` 多网融合 | 同一节点拥有 ≥2 个不同 /24 的内网 IP | high |
| `frp` FRP 隧道 | JA3/JA4 命中 Go-TLS 客户端指纹 + 长连接/心跳/陌生目的 ≥3 项 | mid~high |
| `clash` Clash/V2Ray | 随机/罕见 SNI + 高频短间隔公网外联 + 持续陌生目的 | mid（陌生 /24 ≥20 → high） |
| `reverse_proxy` 反向代理 | 单内网 IP 对外提供多 Host（≥ `reverse_proxy_hosts`） | mid |
| `unknown_egress` 未知外联 | 内网 → 公网陌生目的持续外联 | low~mid |

**所有规则只产出标签**，不判定违规、不告警外发、不解密。

`looksRandomSNI` 的启发式：主标签长度 + 信息熵 + 元音结构。它是启发式，不是结论，
所以 `clash` 规则要求**三项同时满足**才打 mid。

### 5.2 事件去重（§10.5）

24h 窗口内，同 `type` + 同 `node` 且状态为 `pending`/`confirmed` 的事件不重复建单，
只更新 `evidence`（合并新的观测值）。避免一条隧道每 2 秒生成一条事件。

### 5.3 白名单抑制

四个维度：`cidr` / `ip` / `host` / `node`（node 维度用稳定 `NodeKey`，跨重启有效）。

新建白名单时会**回溯**：命中该白名单的 `pending` 事件自动置为 `false_positive`，
返回 `suppressed` 计数。这避免了"配了白名单但历史告警还挂在那里"的困惑。

### 5.4 复核闭环与审计

三个动作：`confirm`（确认归档）/ `false_positive`（误报加白）/ `defer`（暂缓）。

- `false_positive` 会**自动创建白名单**（这是"一次判定，长期生效"的关键）。
- 每次操作写 `audit` 表：`actor`（登录身份，未启用认证时取 ClientIP）、动作、对象、备注。
- 事件详情页把创建 + 复核历史拼成时间线。

---

## 6. 资产、端口与主动发现

### 6.1 资产库同步

**代码**：`internal/api/server.go: syncAssets / syncAssetsThrottled`

拓扑节点 → `assets` 表：

- 新节点 → `unarchived`（未归档）资产，`location` 取探针位置
- 已存在 → 刷新 IP/MAC/last_seen；**已归档资产不覆盖用户填写的物理位置**
- 未归档主机离线超 `unarchived_offline_hours`（72h）→ 自动清理

⚠️ 遍历必须用 `AllNodes()` 而不是 `Snapshot()`：后者会隐藏已聚合网段的成员，
导致"网段内超过阈值的主机永远进不了资产库"（1.4 的 P0，"账外资产发现静默失效"）。

⚠️ 这个函数对每台主机做一次 SELECT + 一次 UPSERT。1 万台主机 = 2 万次 SQLite 往返，
而 store 是**单连接**（见 7.3），这段时间所有其它请求都在排队。
所以 1.2 加了 `syncAssetsThrottled`：5 秒节流 + 防重入，并发请求读到上一轮快照即可。

### 6.2 端口提取

从会话五元组提取内网侧端口，写 `ports` 表（`source=traffic`）。

upsert 的冲突键是 `(node_key, ip, port, proto)`，并带**指纹保护**：

```sql
ON CONFLICT(node_key, ip, port, proto) DO UPDATE SET
  last_seen = excluded.last_seen,
  product = CASE WHEN excluded.product <> '' THEN excluded.product ELSE ports.product END,
  ...
```

原因：同一端口会被"流量提取"（无指纹）与"主动发现"（有指纹）各写一次，
直接覆盖会让辛苦扫到的产品名被一次流量写入清空。

### 6.3 台账对照

**代码**：`internal/ledger/ledger.go`（纯逻辑，无 IO）

CSV 表头中英文别名容错（`ip/IP地址/地址`、`department/归属单位/部门`…），
处理 UTF-8 BOM、列数不齐、`AA-BB-CC` 形式 MAC、非法/重复 IP 跳过计数。

四类差异：

| 分类 | 含义 | 判定 |
|---|---|---|
| 在册在网 | 台账有、网内也有 | IP 命中 |
| **台账外设备** | 网内有、台账没有 | IP 与 MAC 都不命中 |
| 台账僵尸 | 台账有、网内从未发现 | 台账条目无观测 |
| IP 不符 | MAC 对得上、IP 不同 | 先 IP 未命中，再 MAC 命中 |

匹配顺序很重要：**先按 IP，再按 MAC**。反过来会把"某 IP 换了一台机器"误判成"同机换 IP"。

⚠️ 未导入台账时**不能**把全部主机标成"台账外"——差异是相对权威台账算出来的，
没有参照系就没有差异。前端在 `ledger_total == 0` 时显示导入引导，而不是一屏红字。

### 6.4 主动发现（1.2）

**代码**：`internal/probe/`（扫描/指纹/编排）+ `internal/discover`（执行器）+ `internal/api/discover.go`（HTTP）

参考灯塔（ARL）的侦察流水线，但**不把 masscan / nmap 当作前提**。

| 阶段 | 实现 | 关键取舍 |
|---|---|---|
| 端口扫描 | 纯 Go TCP connect，worker pool + 令牌桶 | 无需 root、无外部依赖；代价是慢 |
| 端口计划 | `quick` 108 / `standard` 1149 / `full` 65535 | 端口表自持，nmap top-ports 按公网频率排序，内网值钱的是 445/3389/8080/3306 |
| 限速 | 全局默认 800 pps | 政务网老交换机被 5000pps 扫过会管理面失联 |
| 服务指纹 | HTTP / TLS / banner / favicon mmh3，70 条规则 | 优先国产设备（泛微/致远/海康/H3C…），未命中只留原文 |
| 编排 | 先端口，只有真开了才认指纹；单主机指纹上限 32 | 对 65535 个端口各发一次 HTTP 是小型 DoS，不是盘点 |
| 长期运行 | 时间窗口 / 指数退避 / 已知主机降频 | 手动触发与周期任务共用一份逻辑 |

**限速器的实现细节**：用"下次可发送时刻"（`next`）而不是 ticker。
ticker 在低频时纯空转，高频并发下还要额外加锁；`next` 方案在 `wait()` 里
`now < next` 才 sleep，天然无空转。

**指纹的四类证据**：

1. HTTP：状态码、`Server` 头、页面标题（去 HTML 实体、压空白、截断 200）、跳转地址
2. TLS：证书 CN、**SAN**（现代证书常常只写 SAN，CN 留空）、签发者、到期日、自签判定
3. banner：只发送只读探针（`PING` / `version` / `srvr`），不发送任何写命令
4. favicon：Shodan 兼容哈希——base64（每 76 字符换行 + 末尾换行）→ murmur3 x86-32 seed 0 → 有符号 int32

⚠️ **明文 HTTP 打到 TLS 端口**时 nginx/Go 会返回 `400 + "plain HTTP request was sent to HTTPS port"`。
不识别这条特征，整个 HTTPS 站点会被当成"明文 400 页面"，证书情报全丢。
指纹器识别后会继续尝试 https。

### 6.5 nmap 扫描（可选）

`POST /api/ports/scan` 调用系统 nmap（`nmap_path` / `scan_ports` / `scan_rate`）。
两条路并存而不是替换：nmap 的 `-sV` 版本识别更强，能装就继续用；
装不上不应该等于"没有主动发现能力"。

---

## 7. 存储层

**代码**：`internal/store/sqlite.go`（约 1300 行，含全部 SQL）

### 7.1 表结构

| 表 | 主键 / 唯一键 | 说明 |
|---|---|---|
| `nodes` | `id`，`node_key` 索引 | 拓扑节点持久化 |
| `edges` | `id`，`key` | 边（含 `kind` 区分流量/归属） |
| `sessions` | `id` + 时间 | 退出时补写未落库会话 |
| `events` | `id` | 风险事件，`status` 索引 |
| `whitelist` | `id` | 四维白名单 |
| `domains` | `id` | 网络域（名称 + CIDR 列表） |
| `config` | `key` | 运行时配置持久化 |
| `audit` | `id` | 操作留痕 |
| `assets` | `node_key` UNIQUE | 主机资产库 |
| `ports` | `(node_key, ip, port, proto)` UNIQUE | 端口记录 + 指纹 |
| `probes` | `probe_id` | 探针注册表 |
| `ledger` | `ip` UNIQUE | 人工台账快照 |

索引：`idx_ports_key` / `idx_ports_ip` / `idx_assets_status` / `idx_events_status` / `idx_events_type`。

### 7.2 迁移策略

**只加列，不重建表**（`ALTER TABLE ... ADD COLUMN`）。

理由：这些表是历史累积的观测数据。重建一次等于把所有"首次发现时间"重置为迁移当天，
账实对照会全部失真。代价是旧列无法删除/改类型——可接受。

### 7.3 并发模型

```go
db.SetMaxOpenConns(1)          // 单连接
db.Exec("PRAGMA journal_mode=WAL")
```

- **单连接**：SQLite 写锁是库级的，多连接只会把"写冲突"变成"busy 重试"。
  单连接把排队放在 Go 侧，行为可预测。
- **WAL**：读不被写阻塞（同进程内的读也会走 WAL）。
- 代价：**任何一次慢查询都会卡住所有请求**。这就是为什么 6.1 要节流、8.2 要限流列表长度。

### 7.4 容量护栏与保留期

| 护栏 | 位置 | 默认 |
|---|---|---|
| 列表单页条数 | `internal/api/paging.go` | 2000（显式 `limit` 时硬上限 5000） |
| 列表模糊搜索关键字 | 同上 `maxKeywordLen` | 64 字符（按 rune 截断） |
| 请求体 | `internal/api/middleware_security.go` | 2MB（PCAP 200MB / 探针 64MB / 台账 16MB） |
| 审计保留 | `maintenanceLoop`（6 小时一次，启动先跑一次） | 90 天 |
| 事件保留 | 同上，**只删已处置的** | 180 天 |
| 会话表 | `parser/aggregator.go` | 20 万条 |
| 发现任务表 | `internal/api/discover.go` | 内存保留 50 个 |

> 审计清理函数 `DeleteAuditLogsBefore` 在 1.0 就写好了，但**没有任何调用点**——
> `audit_retention_days` 因此是个"改了没用"的开关。1.2 把它接到 `maintenanceLoop`，
> 并给事件补上同样的保留期（此前事件表完全没有清理策略，只增不减）。

**列表分页（1.3.1 起为真分页）**

三张列表（事件 / 资产 / 端口）统一走 `limit` + `offset` + `q`：

| 环节 | 做法 | 为什么 |
|---|---|---|
| 筛选下推 | `q` 转成 SQL `LIKE`，多列 `OR` | 前端本地筛选 + 服务端分页 = 筛选只覆盖当前页，用户会得出"这台机器不存在"的错误结论 |
| 列表与计数同源 | `eventWhere(f)` / `assetWhere(f)` / `portWhere(f)` 是唯一构造点 | 两边各拼一遍 WHERE，"共 N 条"迟早和列表对不上 |
| LIKE 转义 | `%` `_` `\` 全部转义 + `ESCAPE '\'` | 不转义时搜 `%` 命中全部，用户只当搜索坏了 |
| 排序键兜底 | 端口 `ORDER BY ip, port, id`、资产补 `node_key` | 排序键不唯一时，同一行可能在两页都出现、或两页都不出现 |
| 过期响应 | 前端请求序号 `seq`，不匹配就丢弃 | 快速输入时先发的响应可能后到，会把界面刷成旧结果 |

前端三页的页大小：事件 20、资产 50、端口 100。超过总数时自动回退一页（删光最后一页的场景）。

---

## 8. API 层

**代码**：`internal/api/server.go`（2200 行）+ `discover.go` / `paging.go` / `validate.go` / `middleware_security.go`

### 8.1 路由与三级权限

写死在路由表上，看一眼就知道谁能调什么：

| 分组 | 角色 | 典型接口 |
|---|---|---|
| `ro` | viewer | 拓扑、事件、资产、端口、台账、审计、配置读取 |
| `rw` | operator | 复核、白名单增改、PCAP 导入、探针触发、抓包启停、归档、扫描 |
| `adm` | admin | 改配置、删白名单/域名/资产/台账/探针 |

未启用认证（`auth.mode=none`）时 `auth.Role` 恒为 `admin`，三组等价放行。

中间件顺序（**顺序本身是设计**）：

```
logging → Recovery → securityHeaders → bodyLimit → metrics → cors → auth → 业务路由
```

- `logging` 最外层：panic 被 Recovery 兜住后，日志层仍能拿到 500 并收尾。
- `securityHeaders` / `bodyLimit` 在认证之前：未认证请求、404、静态资源同样需要防护。

### 8.2 安全响应头与请求体上限

`securityHeaders()` 下发：

| 头 | 值 | 挡什么 |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | 上传的文本被当脚本执行 |
| `X-Frame-Options` | `DENY` | 点击劫持（老浏览器） |
| `Content-Security-Policy` | 见下 | 外部脚本注入 / eval / 表单外发 / iframe 套用 |
| `Referrer-Policy` | `same-origin` | 内网地址顺着 Referer 漏给外部 |
| `Permissions-Policy` | 关闭地理位置/麦克风/摄像头 | — |

```
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self' data:; connect-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

`'unsafe-inline'` 是刻意保留的：产品零构建、零 CDN（内网离线可用），页面全是内联 script/style。
即便如此，CSP 仍挡住三件真实的事：外部脚本、`eval`、表单提交到外站。

`bodyLimit()` 按路径给上限，默认 2MB。**必须在中间件做**：让 handler 各自加，
"新增接口时忘了加"几乎是必然事件。

### 8.3 输入校验

`internal/api/validate.go`：

- 长度一律按**字符数**（`utf8.RuneCountInString`）——中文按字节算会被误判。
- 名称 128、备注 2000、描述 512、白名单值 256、网段 64 个。
- 网段必须能被 `net.ParseCIDR` 解析；颜色必须 `#RRGGBB`（这个值会进 SVG/CSS，不校验等于样式注入）。

### 8.4 错误语义

- 业务错误（4xx）直接给出人话，前端原样显示。
- **内部错误（500）统一走 `internalError()`**：详细原因进日志（带 `request_id`），
  客户端只拿到"服务内部错误"。
  直接把 `err.Error()` 回前端会漏出 SQL 语句、表名、文件路径——
  对内网自用也许无所谓，但开源产品会被部署到客户环境。

### 8.5 静态资源

`web/` 通过 `embed.FS` 内嵌；`staticHandler` 拒绝 `..` 路径穿越；
未匹配的 `/api/*` 返回 **JSON 404**（不是 SPA 兜底 HTML），
否则前端 `JSON.parse` 会抛 `Unexpected token '<'`。

---

## 9. 前端

**代码**：`web/`（9 个页面 + 4 个共享资源，约 6000 行）

### 9.1 零构建架构

没有 npm / webpack / CDN。每个页面是一个 HTML，内联业务 JS，
共享 `theme.css`（设计令牌 + 组件）、`app.js`（工具/骨架/导航/门禁）、`topo.js`（拓扑渲染）。

**为什么**：内网离线部署，任何外部 CDN 都可能是"页面打不开"的原因；
零构建也意味着改一行 CSS 刷新即可，不需要工具链。

**代价**：没有类型检查、没有组件复用机制、大型页面（`assets.html` 745 行）偏长。
换取的是"拷过去就能跑"。

### 9.2 设计系统

`theme.css` 是唯一的设计来源，约 1060 行：

- 设计令牌：颜色 / 间距 / 圆角 / 阴影 / 动效曲线 / 字号
- 组件：按钮、输入、表格、卡片、模态、开关、徽标、toast、空态、骨架屏
- `prefers-reduced-motion` 全局降级

**按钮位置统一**：全站操作按钮在页头工具栏或弹窗底部右侧，不散落在表格里
（表格行内只保留"复核/编辑/删除"这类上下文操作）。

### 9.3 拓扑渲染引擎（`topo.js`，约 1070 行）

自绘 SVG，不用 Cytoscape（外网依赖 + 体积）。

| 步骤 | 做法 |
|---|---|
| 分层 | 按节点类型分层（外部 → 核心 → 汇聚 → 接入 → 终端），层内按网段聚簇 |
| 连线 | 正交折线（`elbow()`），同层走下方绕行，跨层走中间 |
| 图标 | 内联 SVG 符号（路由器/交换机/防火墙/服务器/终端/云/子网/代理） |
| 风险 | 节点描边三色（high/mid/low），异常锚点加红色虚环 |
| 大图保护 | 节点 > 阈值时隐藏标签（聚合节点保留），提示条说明"缩放后可查看局部" |
| 交互 | 滚轮缩放、拖拽平移、框选、右键菜单、hover 高亮邻接、双击下钻、导出 PNG/SVG |
| minimap | 右下角缩略图，视口框可拖 |

### 9.4 事件委托与 XSS 防护

全站不使用内联 `onclick`，统一 `data-act` + `document` 级事件委托（`UI.on`）。

原因有两个：① 内联事件在 CSP 下受限；② 内联 `onclick="del('xxx')"` 里拼字符串
是存储型 XSS 的经典入口。

文本一律过 `UI.esc()`（转义 `& < > " '`），属性值过 `UI.escAttr()`（额外转义换行与反斜杠）。

**动态验证**（不是只看代码）：把 `<img src=x onerror=...>` 写进台账备注 / 域名 / 白名单 / 探针位置，
再打开各页面，断言 ① DOM 里不出现 `img[src=x]`、② `window.__xss` 未被设置、
③ payload 以文本形式可见。三张网同时成立才算过。

### 9.5 响应式

- `≤1200px`：网格降到 2 列，隐藏品牌英文名
- `≤960px`：内容 padding 收紧，页码标题缩小
- `≤760px`：侧栏改为**顶部横向滚动导航**（不是 `display:none`，否则手机上无法切页），
  隐藏顶栏全局搜索与用户名，弹窗贴边

> 早期版本在 `760px` 直接把侧栏 `display:none`，等于手机上没有任何导航入口；
> 同时顶栏的搜索框与用户胶囊固定宽度，整页横向溢出 89px。两处都已修。

---

## 10. 可观测性

**代码**：`internal/logging/`、`internal/metrics/`

- **结构化日志**：slog，`text` / `json` 两种格式；每条请求带 `request_id`；
  访问日志字段固定（method/path/status/duration/bytes/client.ip/route）。
- **日志级别热改**：`PUT /api/config {log_level}` 立即生效（`slog.LevelVar`）。
  日志格式与 `/metrics` 开关涉及 Handler 与路由注册，只能重启生效——**显式不假装热改**。
- **Prometheus 指标**：`/metrics`，三种放行方式（`metrics_token` / admin 会话 / 未启用认证时的回环地址）。
  指标含节点数、会话数、事件数、丢弃会话数、HTTP 直方图。
- **审计**：所有写操作落 `audit` 表，`actor` 可追溯到登录身份或来源 IP。

---

## 11. 性能与容量

实测环境：Ryzen 5 5600X，单核，Windows / Go 1.26.10。

| 场景 | 实测 |
|---|---|
| 会话摄入 | 2.17 µs/op（约 46 万会话/秒） |
| 1 万节点 + 3 万边全量快照 | 43 ms（同步周期 2s，余量约 46 倍） |
| 200 个代理 / 1 万条 xff 边推导 | 1 ms |
| 前端首屏（45 节点拓扑，本地） | 约 4.8 s（含 networkidle 等待） |

**容量建议**：

| 规模 | 建议 |
|---|---|
| ≤ 5000 主机 | 默认参数即可 |
| 5000–20000 | 提高 `aggregate_threshold`、关闭实时抓包改用探针、DB 放 SSD |
| 端口记录 > 10 万 | 定期清理或按网段归档（列表已支持服务端分页与搜索） |

---

## 12. 已知边界与设计取舍

| 边界 | 说明 | 是否计划解决 |
|---|---|---|
| 不做 TCP 流重组 | 只见单包，看不到完整会话内容 | 不计划（收益低） |
| 不解密 TLS | 只有 SNI / 证书 / JA3 / JA4 | 永不（合规红线） |
| 单机单进程 | 无分布式调度、无集群 | 定位使然 |
| ~~列表为"护栏式分页"~~ | 1.3.1 已改为真·服务端分页 + 服务端搜索 | **已解决** |
| 无爬虫 | 不产出 URL / 目录清单 | 不计划（授权边界） |
| 指纹长尾 | 70 条规则覆盖不了长尾产品，未命中只留原文 | 持续补规则 |
| 前端无自动化回归 | `make ui`（真浏览器闸门），仍未进 CI | 部分（要下载浏览器） |
| 无 `-race` 本地验证 | 需 gcc，只能靠 CI 三平台 | 否 |

---

## 13. 代码地图

```
cmd/starmap/main.go          装配：配置 → 存储 → 引擎 → 检测 → 路由 → 后台循环
internal/
  api/          HTTP 层（路由/权限/校验/分页/安全中间件/各业务 handler）
  auth/         可选认证：本地账号（bcrypt）+ OIDC（PKCE）+ 会话 + 登录限流
  config/       配置加载与默认值合并
  detect/       五类检测规则 + 调度 + 去重 + 白名单抑制
  discover/     主动发现执行器（手动/定时共用，落库）
  ingest/       PCAP 文件 + 实时抓包
  ledger/       台账 CSV 解析 + 三/四方对照（纯逻辑）
  logging/      slog 初始化 + 访问日志中间件 + request_id
  metrics/      Prometheus 指标 + /metrics 鉴权
  model/        全部数据结构（SystemConfig / Node / Session / RiskEvent / Asset / PortRecord…）
  parser/       报文解析（五元组/MAC/TLS/HTTP/XFF）+ 会话聚合与回收
  probe/        端口扫描、服务指纹、指纹规则、时间窗口、发现编排
  review/       复核动作 + 审计写入
  store/        SQLite 全部 SQL、迁移、分页、保留期清理
  topology/     图引擎：节点/边/聚合/锚点/归属边/XFF/持久化
  version/      版本单一来源
web/            前端（embed）
  assets/theme.css  设计系统
  assets/app.js     工具 / 骨架 / 导航 / 门禁 / 模态 / toast
  assets/topo.js    SVG 拓扑渲染引擎
  assets/api.js     REST 封装 + 列表元信息
  *.html            9 个页面
scripts/        构建/测试/冒烟/截图/部署脚本
testdata/       合成 PCAP 生成器 + 探针模拟器 + 示例台账
docs/           架构、运维、安全、发布说明、设计文档
```

---

## 14. 贡献指南：三个最常见改动

### 14.1 加一条指纹规则

1. 打开 `internal/probe/rules.go`，在 `rules` 切片里加一条：

```go
{Product: "泛微 e-cology", Service: "http", Ports: []int{80, 443, 8080},
 Title: []string{"e-cology", "泛微"}, Version: `(?i)e-cology\s*([\d.]+)`},
```

2. 匹配优先级按切片顺序，**特异性高的放前面**（国产设备 > 中间件 > 通用 Web 服务器）。
3. 跑 `go test ./internal/probe/ -run TestMatchRules` 与规则表一致性用例。
4. 在 `CHANGELOG.md` 记一行。

### 14.2 加一条检测规则

1. 新建 `internal/detect/<name>.go`，实现 `func evalXxx(rc *ruleContext) []model.RiskEvent`。
2. 在 `detector.go: Evaluate()` 里挂上，并写清**阈值与依据**（为什么是这个数）。
3. 补三类测试：命中、不命中（近似诱饵）、白名单抑制。
4. 前端无需改动——事件列表按 `Type` 走 `typeLabel()` 映射，新类型补一条映射即可。

### 14.3 加一个页面

1. 复制一个结构最简单的页面（`whitelist.html`）作为骨架，保留 `sm-topbar` / `smSider` / `sm-main`。
2. 在 `app.js` 的 `NAV` 数组里加一项（分组 + 图标 + 标题）。
3. 页面级 JS 用 `UI.on('act-name', handler)` 绑定 `data-act`，不要用内联 `onclick`。
4. 跑 `go test ./web/`（页面骨架契约测试会校验导航可达与令牌一致）。
5. 跑 `python scripts/ui-smoke.py` 做真浏览器验证。

---

## 附：这份文档没写的东西

- 每个 API 的完整请求/响应字段 → 见 `internal/api/server.go` 的 DTO 定义与 README 的接口表。
- 每个配置项的中文说明 → 见 `web/settings.html` 的字段表（界面上的描述比文档更不容易过期）。
- 每个历史 bug 的完整复盘 → 见 `CHANGELOG.md`，那是这个项目最真实的工程记录。
