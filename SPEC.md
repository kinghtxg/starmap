# StarMap 星图 V1.0 — SPEC（唯一事实来源）

项目：StarMap 星图 · 网内拓扑自动测绘引擎 V1.0（纯 Web B/S，无桌面端）
归属：极客星空实验室 · Apache 2.0
技术栈：Go 1.22 + Gin + gopacket + modernc.org/sqlite（纯 Go 驱动，免 CGO）+ 前端静态页（Tailwind CDN + Cytoscape.js CDN）
本期不做：登录/SSO/RBAC（仅留 middleware 接口位）、流量解密、漏洞扫描、IDS、APSOC 业务对接。

## 1. 目录结构
```
starmap/
├── cmd/starmap/main.go            # 入口：装配各模块，启动 HTTP
├── internal/
│   ├── config/config.go           # 配置加载（config.yaml + 默认值）
│   ├── model/model.go             # 全部数据结构（见 §3）
│   ├── store/sqlite.go            # SQLite 持久化（schema + CRUD）
│   ├── ingest/capture.go          # 网卡实时抓包（gopacket/pcap，多网卡）
│   ├── ingest/pcapfile.go         # PCAP/PCAPNG 文件导入
│   ├── ingest/probe.go            # 远端探针 HTTP 上报接收（POST /api/ingest/probe）
│   ├── parser/parser.go           # 报文解析：五元组/MAC/TTL/会话/TLS/JA3/JA4/SNI/Host
│   ├── parser/ja3.go              # JA3/JA3S 计算；ja4.go JA4 计算
│   ├── topology/engine.go         # 拓扑生长引擎（节点/链路/聚合/老化/降噪/NAT修复）
│   ├── detect/detector.go         # 检测调度器 + 规则接口
│   ├── detect/frp.go              # FRP 三重校验
│   ├── detect/clash.go            # Clash/V2Ray
│   ├── detect/reverseproxy.go     # 反代/未知出口
│   ├── detect/multinet.go         # 多网域融合检测
│   ├── probe/scan.go              # 主动探测 ARP/ICMP/Traceroute（默认关闭）
│   ├── review/review.go           # 事件复核/归档/白名单自动加白/审计留痕
│   └── api/server.go              # Gin 路由 + 全部 REST API + 静态文件托管
├── web/                           # 前端静态资源（index.html 等，embed.FS 内嵌）
├── configs/config.yaml            # 默认配置
├── scripts/deploy.sh              # Linux 一键部署
├── testdata/                      # 合成 PCAP 生成器 + 测试数据
├── go.mod / README.md / LICENSE(Apache-2.0)
```

## 2. 数据流
抓包/PCAP/探针 → PacketSource(channel) → parser → Session/AggregatedFlow → topology.Engine.Ingest(flow) → detect.Detector.Evaluate(周期性) → RiskEvent → review（确认/误报/暂缓）→ store。API 层读取 store+engine 快照供前端。

## 3. 核心数据结构（model 包，JSON tag 即 API 字段）
- Node{ID, IPs[], MAC, FirstSeen, LastSeen, Domain(string 网络域), Labels[], RiskLevel(none|low|mid|high), Active}
  - 派生身份字段（快照计算，不落库，1.5.0）：Role(gateway|nas|dns|db|web|remote|server|host|external)、Roles[]、Services[]、Ports[]、InboundPeers、GatewayFor、TTL、OSHint、Software[]
  - 安全检查字段（快照计算，不落库，1.5.0）：`Overseas`(事实：非中国大陆 IPv4 公网)、
    `TunnelSuspect`(事实：疑似隧道)、`IntelVerdict`(malicious|suspicious|clean|unknown)、
    `IntelScore`、`IntelTags[]`、`NodeKey`、`Whitelisted`、`Highlight`(结论，见 §4.2)。
    **事实与结论必须分开**：加白只压 `Highlight`，不改写 `Overseas`——观测结果不因人为豁免而改变。
  - 端口明细（快照计算，不落库，1.5.0）：`OutPorts[]`（作为客户端连出去的**对方端口**）、
    `InPorts[]`（作为服务端**被连的本端端口**）。两者不可合并：同一个 443 在两侧含义相反。
- IntelRecord{Indicator(唯一键), Kind(ip|cidr|domain), Verdict(malicious|suspicious|clean|unknown),
  Score(0~100), Tags[], Source, Version(int64), UpdatedAt(结论时间，判新旧以此为准),
  ReceivedAt(入库墙钟), ExpiresAt*(空=长期有效，仅回源写入的记录有值), Raw}
- IntelIngestStat{Received, Inserted, Updated, Unchanged, Stale, Conflict, Invalid}（一次推送的六种结果计数）
- PortUse{Port, Proto, Sessions(首次观测计一次), Peers(≤8), Bytes}（快照派生，不落库）
- Edge{ID, SrcID, DstID, Protocol, Bytes, Packets, FirstSeen, LastSeen, Active}
- TopoSnapshot{Nodes[], Edges[], Stats{...}, GeneratedAt}（GET /api/topology 返回）
- Session{FiveTuple{SrcIP,DstIP,SrcPort,DstPort,Proto}, MAC, DstMAC, StartTTL, FirstSeen, LastSeen, BytesUp, BytesDown, Packets, SNI, HTTPHost, UserAgent, HTTPServer, JA3, JA4, IsLongConn, HeartbeatIntervalMs, Closed}
- RiskEvent{ID, Type(frp|clash|reverse_proxy|unknown_egress|multi_net), NodeID, Title, Detail, Evidence(map), Status(pending|confirmed|false_positive|deferred), Level(mid|high), CreatedAt, UpdatedAt, ReviewNote, Reviewer}
- WhitelistEntry{ID, Kind(cidr|ip|host|node), Value, Note, CreatedAt}
- NetDomain{ID, Name(gov|office|internet|prod|自定义), CIDRs[], Color}
- AuditLog{ID, Actor, Action, Target, Detail, CreatedAt}
- Config：系统参数（探测开关、抓包网卡、老化时长、聚合阈值等）

## 4. 拓扑引擎规则
- 每个内网 IP → 节点候选；同 MAC 多 IP 合并为一个节点
- 同 /24 网段节点数 > 聚合阈值(默认 20) → 聚合为子网节点（可下钻）
- 会话字节 < 阈值 或 持续时间 < 2s 且包数 < 4 → 降噪不建边
- 边超过 aging_seconds(默认 86400) 无流量 → Active=false 灰度
- NAT 修复：以 MAC+首跳网关推断真实源，避免 NAT 后链路错乱
- 对外公网 IP 不逐一建节点，按 /24 聚合为"外部聚合节点"
- 边类型：流量边（tcp/udp）、`owner`（网段归属，无流量也画）、`gateway`（主机→网关出网路径，与真实边互斥）、`xff`（七层转发关系）
- 非设备地址（多播/广播/回环/未指定）不建节点、不建边，且在降噪判定**之前**拦截
- 网关显式建节点：公网流量的首跳 MAC 是网关唯一可见的身份，按 MAC 建节点并标 `gateway`

### 4.1 设备身份识别（1.5.0）
- 只用被动证据，且证据可追溯；**没有正面证据不给角色**（界面显示"未识别"）
- 角色 → 证据：`gateway`=被当作首跳网关；`dns/db/web/remote`=作为服务端在对应端口被访问且有入向对端；`nas`=NFS/AFP/群晖 DSM 单见即成立、仅 445/139 需 ≥2 对端；`server`=有入向连接且端口不在目录；`host`=本次观测到它主动发包
- 方向判定：本机访问外部 53 端口是 DNS **客户端**，不构成 `dns` 角色
- 服务画像跨重启恢复：端口库 `source=traffic` 的记录可恢复端口与"曾有人连过"；扫描来源不算
- 系统栈：TTL 取观测最大值 → 网络设备(>128)/Windows(65~128)/类 Unix(33~64)，原始 TTL 一并展示
- 软件指纹：明文 HTTP 的 Server / X-Powered-By / User-Agent；UA 归客户端、Server 归服务端，方向靠端口推断，两端皆为服务端口时不记录

### 4.2 公网折叠与标红外置（1.5.0）

- 默认把 `Highlight=false` 的公网节点折叠为单一 `cloud:internet` 节点，**视图行为**：
  `foldExternal(nodes, edges)` 为纯函数，不改快照、不落库，返回新集合；展开后原状恢复
- **`Highlight`（结论）由后端 `buildNodeJSON` 唯一计算**，条件为「未被加白 且（`Overseas` 或 `TunnelSuspect` 或 `IntelVerdict∈{malicious,suspicious}` 或 `RiskLevel∈{mid,high}`）」
- `Highlight=true` 的节点**不参与折叠**，留在云外红色虚环并标「待核查」；加白后标「已加白」并重新计入折叠
- 前端**不得自行判断**"是否国外/是否风险"，只渲染 `Highlight`（规则只留一处，否则前后端必然漂移）
- 折叠后的边按「方向 + 协议 + Kind」合并并累加 `_folded` 计数，悬停展示「合并 N 条」；无可折叠节点时云节点不出现
- 白名单查询在出图路径上带 2s 缓存，增删改后立即失效

### 4.3 本地情报库与覆盖语义（1.5.0）

- 出图路径**只查本地库**（批量 `IN` 查询，每 400 键一批）；回源是人工动作，不是出图副作用
- 覆盖：`version` 优先，其次 `updated_at`；仅当 `excluded.intel_ver > 库内 ver` 或「版本相等且 `updated_at >=` 库内」时更新
  - 乱序/重放的旧版本必须被拒绝并计入 `stale`，**不能让旧数据把新结论洗回去**
  - `updated_at` 相等且结论相同视为幂等重推（`unchanged`），不产生写
  - `updated_at` 相等但结论不同 → `conflict`，**拒绝**：同一版本必须对应同一结论，否则等于允许无声改写已发布的判定；改判要升版本
- 空 `source` 不覆盖库内已有 `source`
- 单条非法记录跳过并计入 `invalid`，不 abort 整批
- 指标规范化：IPv4 `To4().String()`；`/32` 归一为单 IP；域名小写去引号；
  **纯数字残缺 IPv4（如 `1.2.3`）判非法**，不当域名
- 外部聚合节点的情报键需同时试「剥掩码的单 IP」与「整段 CIDR」
- 回源只允许公网地址（`ErrPrivateIP` → 400）；本地库允许存内网 IOC（失陷主机场景）
- 过期语义：`ExpiresAt` 到期后允许重新回源；未配回源时返回过期记录并显式标注「数据已过有效期」

### 4.4 端口使用统计（1.5.0）

- 两个方向分开记，语义严格区分：`OutPorts` = 本节点作为客户端连出去的对端端口；
  `InPorts` = 本节点作为服务端被连的本端端口
- 与 §4.1 的 `Ports` 不是同一口径：`Ports` 只含「目的在内网 + 端口在服务端口表内」的会话（角色推断用，口径必须稳）；
  端口明细含全部方向与全部端口（含公网与高端口），是给人看的现场证据
- `Sessions` 只在**首次观测到该会话**时 +1；同一会话的重复上报与字节增量不重复计数
- 观测点必须在**降噪判定之前**：短小会话（一次 TLS 握手）正是要回答的问题，不能因为不画边就丢掉
- 上限：每节点 32 个不同端口（满了丢弃新端口而非淘汰旧端口）、每端口 8 个对端、出图 12 个
- 排序按会话数降序、其次字节、再次端口号（map 迭代无序会让界面每次刷新都跳）
- 内存态，重启后随新流量重建；内网 `/24` 聚合节点暂不合并成员端口

## 5. 识别规则（只打标签，不定性）
- FRP（三项满足其二即标记 mid，三项全中 high）：JA3/JA4 匹配 Go-TLS 客户端指纹表；TCP 连接时长 > 1h 且保活；周期性小包心跳（间隔方差小、payload<64B）
- Clash/V2Ray：TLS SNI 随机/罕见域 + 高频短间隔公网外联 + 持续陌生目的节点
- 反代：单内网 IP 作为**服务端**对外映射 Host 域名数 > 阈值(默认 10)（只看目的为内网的会话）
- 未知出口：内网设备对外服务端口/链路数突增超基线
- 多网融合：同节点（或同 MAC/同路由）流量命中 ≥2 个 NetDomain → high
- 跨域证据口径（1.5.0 收紧）：多播/广播/回环/链路本地对端不算另一域；仅被 `0.0.0.0/0` 通配域兜底命中（最长前缀 `ones==0`）不算跨域证据
- Clash 随机域名启发式（1.5.0 收紧）：主标签含数字 + 长度 ≥12 + 熵 > `0.9×log2(len)`；时间窗锚点取节点各自最新活动时间（墙钟会在历史 PCAP 上整条静默，全局最新时间会让多份 PCAP 互相裁剪）
- 所有事件先过白名单抑制（命中 whitelist 不产生事件/已有事件自动 false_positive）

## 6. REST API（/api 前缀，JSON）
- GET /api/topology （TopoSnapshot）；GET /api/nodes/{id}
- GET /api/events?status=&type= ；POST /api/events/{id}/review {action: confirm|false_positive|defer, note, reviewer}
- CRUD /api/whitelist ；CRUD /api/domains
- POST /api/ingest/pcap （multipart 上传解析）；POST /api/ingest/probe（探针上报）
- GET/PUT /api/config ；GET /api/audit ；GET /api/stats ；GET /api/health
- POST /api/probe/trigger {type: arp|icmp|traceroute, target}
- **情报（1.5.0）**
  - `POST /api/intel/push`：情报平台推送，鉴权 `X-Intel-Token`（亦接受 `Authorization: Bearer` / `?token=`）。
    未配置令牌 → **403（拒绝接收，不是放行）**；令牌不符 → 401；单批 > 20000 条 → 413。
    请求体接受 `{source, verdict, records|indicators|data|items[]}`、裸数组、纯文本/CSV（配 `?verdict=`）。
    成功返回 `{source, stat:{received,inserted,updated,unchanged,stale,conflict,invalid}}`；
    `stale>0` 时附 `warning`、`conflict>0` 时附 `conflict_hint`、`invalid>0` 时附 `invalid_hint`。
    **200 不代表全部生效。**
  - `GET /api/intel?verdict=&limit=&offset=` 本地库分页；`GET /api/intel/stats` 概况（含 `push_token_set`/`remote_enabled`/`retention_days`）
  - `GET /api/nodes/{id}/ti?refresh=1` 单点查询：本地命中 → 回源 → 写回；响应含 `source∈{local,remote,none}`
  - `DELETE /api/intel/{indicator}` 人工纠错（admin）

## 7. 前端页面（web/，深色科技风，严格配色：bg #0F172A，card #1E293B，accent #38BDF8，text #E2E8F0，红 #F87171 橙 #FB923C 绿 #4ADE80，全局低透明拓扑连线动态背景 canvas）
1. index.html 拓扑总览：Cytoscape.js 自动布局(cose)、风险三色、缩放平移拖拽、节点详情侧栏（IP/MAC/域/标签/对端/首见时间）、边粗细=流量、导出 PNG（cy.png）/导出 PDF（jsPDF 包图）
2. events.html 事件工作台：列表+筛选+详情+三操作（确认归档/误报加白/暂缓），操作留痕展示
3. whitelist.html 白名单管理；domains.html 网络域管理
4. ingest.html 数据接入：PCAP 上传、抓包状态、探针说明
5. settings.html 系统配置（探测开关、老化、阈值）；logs.html 审计日志；about.html 关于/版本
统一侧边导航 layout.js，fetch 调 §6 API。

## 8. 测试要求
- testdata/gen_pcap.go：用 gopacket 合成 PCAP，场景：正常办公流量、FRP 特征流量、Clash 特征流量、反代多 Host、跨网域双域流量
- Go 单测：parser（JA3 已知向量）、topology 生长/聚合/老化、四条检测规则、白名单抑制、review 闭环
- 集成测试：启动服务 → 上传合成 PCAP → 断言事件生成与拓扑快照 → review 后断言状态流转

## 9. 交付
可 `go build ./...` 通过；`go test ./...` 通过；README（架构/部署/使用/截图占位）；scripts/deploy.sh；LICENSE Apache-2.0。
Go 路径：export PATH=$HOME/sdk/go/bin:$PATH；GOPATH=$HOME/go；依赖走 GOPROXY=https://goproxy.cn,direct。

## 10. SPEC 补充裁定（PM 审查后，与上文同等效力）
1. JA4：按公开算法规范自研实现（仅用算法字符串格式，不使用 FoxIO 许可数据），README 注明。
2. 会话时长以报文时间戳计算；测试可用构造时间戳的合成 PCAP 覆盖 >1h 场景。
3. 降噪默认：bytes<400 AND duration<2s AND packets<4 → 丢弃不建边（三条件同时满足）。
4. 未知出口基线：1h 滚动窗口统计单节点对外服务端口/链路数；超过 max(3×历史基线, 20) 触发；服务启动后前 10 分钟为学习期不产出该类事件。
5. 事件去重：同 (type, node_id) 且 24h 内已有 status∈{pending,confirmed} 事件 → 仅更新 evidence/UpdatedAt，不新建。
6. 新增 API：GET /api/topology/subnet/{cidr}（聚合节点下钻）；POST /api/capture/start、POST /api/capture/stop、GET /api/capture/status；探针上报 schema：{probe_id, token?, flows:[Session 子集], ts}；事件 Level 映射节点 RiskLevel：high→high(红)、mid→mid(橙)、无事件→none(绿)。
7. 探针 token 为可选配置项 probe_token（配置则校验）。
8. PCAP 上传上限 200MB；审计日志保留 90 天可配；所有时间字段 RFC3339。
9. 多网融合"同路由"判定：同 MAC 或同首跳网关 MAC 命中 ≥2 网络域。
10. 聚合阈值下调时立即重聚合，上调时不拆分已聚合节点（迟滞）。
11. 情报推送鉴权不沿用探针的"未配即放行"：探针写观测，情报写**结论**，匿名可写等于允许诬告与洗白。
12. `stale` 语义：旧版本数据**拒收而非静默丢弃**——必须进响应与审计，否则推送方永远不知道自己推的是旧货。
13. `conflict` 与 `stale` 必须分开计数：前者是"同版本改结论"（该升版本号），后者是"版本比库里旧"（该查时钟），
    合成一个会让推送方朝错误方向修。
14. 新增配置键：`intel_push_token`(默认空=拒收推送)、`intel_retention_days`(默认 90，0=不清理)；沿用 `ti_enabled`/`ti_endpoint`/`ti_api_key`/`ti_timeout_ms`/`ti_cache_seconds` 作回源参数。
