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
- Edge{ID, SrcID, DstID, Protocol, Bytes, Packets, FirstSeen, LastSeen, Active}
- TopoSnapshot{Nodes[], Edges[], Stats{...}, GeneratedAt}（GET /api/topology 返回）
- Session{FiveTuple{SrcIP,DstIP,SrcPort,DstPort,Proto}, MAC, StartTTL, FirstSeen, LastSeen, BytesUp, BytesDown, Packets, SNI, HTTPHost, JA3, JA4, IsLongConn, HeartbeatIntervalMs, Closed}
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

## 5. 识别规则（只打标签，不定性）
- FRP（三项满足其二即标记 mid，三项全中 high）：JA3/JA4 匹配 Go-TLS 客户端指纹表；TCP 连接时长 > 1h 且保活；周期性小包心跳（间隔方差小、payload<64B）
- Clash/V2Ray：TLS SNI 随机/罕见域 + 高频短间隔公网外联 + 持续陌生目的节点
- 反代：单内网 IP 对外映射 Host 域名数 > 阈值(默认 10)
- 未知出口：内网设备对外服务端口/链路数突增超基线
- 多网融合：同节点（或同 MAC/同路由）流量命中 ≥2 个 NetDomain → high
- 所有事件先过白名单抑制（命中 whitelist 不产生事件/已有事件自动 false_positive）

## 6. REST API（/api 前缀，JSON）
- GET /api/topology （TopoSnapshot）；GET /api/nodes/{id}
- GET /api/events?status=&type= ；POST /api/events/{id}/review {action: confirm|false_positive|defer, note, reviewer}
- CRUD /api/whitelist ；CRUD /api/domains
- POST /api/ingest/pcap （multipart 上传解析）；POST /api/ingest/probe（探针上报）
- GET/PUT /api/config ；GET /api/audit ；GET /api/stats ；GET /api/health
- POST /api/probe/trigger {type: arp|icmp|traceroute, target}

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
