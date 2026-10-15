# StarMap 星图 V1.1 — 数据接入 v2（Data Ingest v2）产品设计文档

> 文档编号：PM-DATA-INGEST-V2-DESIGN
> 撰写：Product Owner（极客星空安全实验室）· 日期：2026-10-15
> 对应需求：V1.1 五项需求之 **第 3 项（数据接入 v2）** + **第 4 项（账号/SSO）合规边界裁定**
> 代码基线：`starmap` @ commit `fe08fc2`（"baseline: StarMap V1.0 before V1.1 refactor"）
> 状态：待开发评审 · 本文全部结论均附代码行号证据，无证据处已显式标注「待确认」

---

## 0. 范围与合规红线声明（不可逾越）

### 0.1 本文档范围

| 项 | 是否本文档范围 | 说明 |
|---|---|---|
| 第 3 项 数据接入 v2（PCAP 深度分析 / 探针推送管理 / 自生长发现） | ✅ **完整负责** | 现状诊断 → 目标 → 功能 → API → 前端 → 验收 → 排期 |
| 第 4 项 账号系统 + APSSO 的**合规边界裁定** | ✅ **负责裁定** | 只给结论与最小接口约束，实现设计另开 `PM-AUTH-SSO-DESIGN` |
| 第 1 项 UI 重构标准 | ⚠️ **部分涉及** | 仅约束 `web/ingest.html`：按钮位置、动画、去 CDN、自绘图表 |
| 第 2 项 拓扑图范式 | ❌ 不在本文 | 另开文档 |
| 第 5 项 P0 自动整改 | ⚠️ **部分涉及** | 只处理与数据接入强相关的 P1-1/P1-2/P1-4；P0-2 作为**强依赖**列出 |

### 0.2 合规红线（本文档任何设计不得突破）

StarMap 只做「**发现 + 打标签**」。以下行为**永久禁止**，任何需求、任何实现、任何文案都不得触碰：

1. **不解密**：不还原 TLS 应用数据、不导入私钥、不做中间人。仅解析 ClientHello 明文元数据（`internal/parser/parser.go:113-228`）。
2. **不定性**：不输出"违规/违法/攻击/入侵/违规外联"结论。所有产出物称"标签 / 提示 / 特征"，不称"判定 / 处置 / 告警定性"。
3. **不封禁、不做管控执行**：不下发 ACL、不调用防火墙、不改路由、不阻断会话。
4. **不外发数据**：不向任何外部系统/公网推送数据、告警、日志、遥测。
5. **不做主动发包的能力默认关闭**：ARP/ICMP/Traceroute 主动探测默认 `false`（`internal/config/config.go:16`、`configs/config.yaml:2`），且**不得纳入自生长自动编排**（见 §3.3.3 裁定）。

**本文档中被剔除的候选功能**（曾考虑但触碰红线，已删除，不得回补）：
- ❌ "判定为违规外联" —— PCAP 分析产出改为"异常流量提示（hints）"，文案固定为"建议人工核查"。
- ❌ "自动阻断异常会话" —— 无任何管控执行面。
- ❌ "上报上级 / 联动 SOC / 推送告警" —— 无外发通道。
- ❌ "自生长自动开启主动探测扫描" —— 主动发包必须人工显式开启。
- ❌ "探针反向接收服务端指令下发抓包策略" —— 探针仅单向上报，服务端不下发指令（避免探针变成管控执行点）。

### 0.3 硬约束（工程）

| 约束 | 要求 |
|---|---|
| 内网离线部署 | **禁止任何 CDN / 外网资源依赖**。新增 CSS/JS 一律放 `web/assets/` 由 `web/embed.go`（embed.FS）内嵌。 |
| 前端无构建步骤 | 原生 HTML/CSS/JS，禁 Webpack/Vite/npm 产物 |
| 图表 | 禁止 ECharts/Chart.js/D3 CDN。用原生 SVG 或 Canvas 自绘（≤200 行 JS） |
| 单二进制 | 新增依赖需为纯 Go（免 CGO），或走 `-tags pcap` 构建标签隔离 |
| 字段风格 | **v2 新增端点一律 `snake_case`**（与现有 `/api/ingest/*` 一致）。现存 `/api/topology`、`/api/events` 的 PascalCase 保持不动，不做破坏性变更 |

---

## 1. 现状诊断（附代码行号证据）

### 1.1 三路接入当前能力总览

| 通道 | 入口 | 现状能力 | 主要缺口 |
|---|---|---|---|
| PCAP 离线导入 | `POST /api/ingest/pcap`（`server.go:841-888`） | 解析报文 → 聚合 → 灌拓扑 → 评估一轮；返回 5 个数字 | 无分析产出、同步阻塞、全量入内存、无进度 |
| 网卡实时抓包 | `POST /api/capture/start|stop`、`GET /api/capture/status`（`server.go:936-1000`） | 多网卡启动、计数 | **停止不生效**（P1-4）；无断流重连；无吞吐/丢包指标 |
| 远端探针上报 | `POST /api/ingest/probe`（`server.go:677-767`） | 收 packets/flows → 聚合 | **无注册、无状态、无批次回执**；**TLS 指纹被静默丢弃**（最严重，见 1.4.3） |

### 1.2 PCAP 导入：能"吃进去"，但"吐不出来"

**证据与问题：**

| # | 问题 | 证据 | 影响 |
|---|---|---|---|
| A1 | 上传文件**全量读入堆内存**，再写临时文件，峰值约 2× 文件 | `internal/ingest/pcapfile.go:85` `io.ReadAll(r)`；`:89-98` `os.CreateTemp` + `tmp.Write(data)` | 200MB 文件 → 峰值 ≥400MB 堆；多并发 OOM（P1-1 已列） |
| A2 | 落盘后再打开文件二次解析 | `pcapfile.go:99` `OpenPCAPFile(tmp.Name())` | 多一次全量磁盘 IO；无 BPF 预过滤/抽样能力 |
| A3 | 上限硬编码 200MB，无分级 | `server.go:32` `MaxPCAPUpload = 200 << 20`；`:848-851` 超限 413 | 内网大抓包（1GB+）无法处理 |
| A4 | 请求**全程同步**，无任务 ID、无进度 | `server.go:864-877`；`ingestInFlight` 在 `:864/865` 只加不读，**从未用于限流** | 大文件浏览器超时；无法取消；并发上传无限 |
| A5 | 每次导入**全量重放**所有历史会话 | `server.go:895-909` `syncTopology()`：`Finalize()` 全量 → 逐条 `Engine.Ingest` → 按 key 去重落库 | O(N) 随导入次数累加（PM 审查记为 O(N²)）；导入第 10 个文件时重放前 9 个的全部会话 |
| A6 | 返回体**无任何分析维度**，只有 5 个标量 | `server.go:881-887`：`filename/packets/sessions/new_events/ingested_at` | 用户花几分钟上传，只得到"12000 报文 / 87 会话"，**无法回答"这包里有什么"** |
| A7 | 前端直接把返回 JSON 打印出来 | `web/ingest.html:103` `UI.esc(JSON.stringify(r))` | 无任何可读性，也无导出 |
| A8 | `http.Server` 无任何超时 | `cmd/starmap/main.go:168` `&http.Server{Addr, Handler}` | 慢连接占满资源（P2-13） |
| A9 | 格式识别仅 4 种魔数 | `pcapfile.go:45-53` | 纳秒 PCAP 已覆盖；**pcapng 分支零测试**（PM 审查 §3.2），实际可靠性待确认 |

### 1.3 会话资产：只写不读的"死数据"

| # | 问题 | 证据 |
|---|---|---|
| B1 | `sessions` 表**没有来源字段**：无法区分某条会话来自哪个 PCAP / 哪次导入 / 哪个探针 | `internal/store/sqlite.go:45-62` 建表语句仅 `five_tuple/mac/start_ttl/...`，无 `source/job_id/probe_id`；**无任何索引** |
| B2 | `SaveSession` 只有 INSERT，无更新/upsert | `sqlite.go:288-298`；`server.go:906-908` 仅在新 key 时调用一次 |
| B3 | `ListSessions` **生产代码零调用**（仅单测使用） | 定义 `sqlite.go:301`；唯一调用点 `internal/store/sqlite_test.go:90`。全仓 grep 无其它调用 → 与 PM 审查 §P1-2 结论一致 |
| B4 | 会话永不淘汰，三处只增 | `parser/parser.go:372-399` Finalize 不淘汰；`topology/engine.go:67` `sessions map[string]*sessState` 只增；`server.go:60` `savedSessions` 只增 |
| B5 | 退出时再全量写一遍，与 `savedSessions` 不共享去重状态 | `main.go:188-191` 退出前 `for ... SaveSession` → **重复行**（注：`savedSessions` 在 `syncTopology` 中做过标记，但退出路径未走该逻辑） |

**结论**：sessions 表当前是纯负担（占空间、无索引、无消费者）。v2 把它**变废为宝**——加来源字段与索引后，直接作为 PCAP 会话明细分页与探针批次明细的持久化载体（见 §3.1.6）。

### 1.4 探针通道：本次诊断发现的**最严重**问题

#### 1.4.1 无注册、无状态、无离线检测

| # | 问题 | 证据 |
|---|---|---|
| C1 | 无探针注册表。schema 中**没有 probes / probe_batches 表** | `internal/store/sqlite.go:22-102` 建表清单：nodes/edges/sessions/events/whitelist/domains/audit/config |
| C2 | 上报回执只有计数，探针无法知道"服务端到底收没收、要不要重传" | `server.go:761-766` 返回 `accepted/total/sessions/new_events`。**无 batch_id、无幂等键** → 网络超时后重传必然重复计数 |
| C3 | 无心跳、无在线状态、无离线检测 | 全文无 `last_seen` 概念（探针侧）。`ProbeReport` 只有 `ProbeID/SentAt/Packets/Metadata`（`internal/ingest/probe.go:14-19`） |
| C4 | 无探针列表/状态 API | `server.go:77-103` 路由清单中无任何 `/api/ingest/probes*` |
| C5 | 配置项中无探针相关参数 | `internal/model/model.go:172-189` `SystemConfig` 只有 `probe_token` |
| C6 | body 限 64MB，但**无批次条数上限、无单探针 QPS 限制** | `server.go:678` `io.LimitReader(c.Request.Body, 64<<20)` |

#### 1.4.2 死代码两处（会被误用）

| # | 问题 | 证据 |
|---|---|---|
| C7 | `ingest.ProbeHandler` **从未注册**，是死代码；且其中通道满即**静默丢包** | 定义 `internal/ingest/probe.go:23-44`；丢弃逻辑 `:36-41`（`select ... default: // 通道满则丢弃`）。实际路由用的是 `server.go:677` 自实现的 `ingestProbe` |
| C8 | `probeTokenMiddleware` 定义但**未挂载** | `server.go:134-152`；路由 `:94` 未使用该中间件（token 校验在 handler 内手写，`:697-709`） |

> PM 审查 P2-1/P2-2 已记为"删除或复用"。**v2 裁定：删除**（见 §8 D16），避免两条语义不同的探针入口并存。

#### 1.4.3 【P0 级功能缺陷】探针上报的 TLS 指纹被静默丢弃，3 条检测规则对探针数据完全失效

这是本次读码新发现、V1.0 审查报告未覆盖的问题。

**链路还原：**
1. 探针上报的 `flows` 元素**确实带有** `sni / http_host / ja3 / ja4 / is_long_conn / heartbeat_interval_ms` 六个字段 —— `server.go:783-788`（`probeFlow` 结构体定义）。前端示例里也写了 `sni`/`ja4` —— `web/ingest.html:76`。
2. 但 `probeFlow.toPackets()` 把 flow 转成**合成报文**时，只填了五元组/MAC/长度/时间戳 —— `server.go:808-819` `mkPkt()` **不含 `Payload` 字段**，也**不传递 SNI/JA3/JA4/HTTPHost/HeartbeatIntervalMs**。
3. 合成报文进入 `Aggregator.Ingest()`（`server.go:748/750`）后，会话的 SNI/JA3/JA4 只能在 `parser.go:349-356` 从 **Payload 中的 TLS ClientHello** 反解 —— 而 Payload 为空。HTTP Host 同理（`parser.go:358-363`）。
4. 心跳需要 ≥3 个采样间隔才能判定（`parser.go:378` `len(st.packetGaps) >= 3`）—— 合成报文每 flow 最多 2 个包，**永远无法判定**，故 `HeartbeatIntervalMs` 恒为 0。

**后果（可验证）：**

| 检测规则 | 依赖字段 | 证据 | 对探针数据 |
|---|---|---|---|
| `frp` | JA3/JA4 + 长连接 + 心跳，三中二 | `internal/detect/frp.go:64-66` | 仅"长连接"1 项可成立 → score 最大 1 < 2 → **永不产出事件** |
| `clash` | SNI 随机性 | `internal/detect/clash.go:82-85` | SNI 恒空 → **失效** |
| `reverse_proxy` | HTTPHost / SNI 域名数 | `internal/detect/reverseproxy.go:25-27` | 恒空 → **失效** |
| `unknown_egress` | 五元组计数 | `reverseproxy.go:91-108` | 可用 |
| `multi_net` | 节点/网络域 | `internal/detect/multinet.go` | 可用 |

**即：5 条规则中 3 条对探针上报数据完全失效，且不报错、不告警、无任何提示。** 与 PM 审查 P0-2 同属"静默少报"这一类最危险的产品缺陷。

> v2 必须修复：探针上报的已解析字段应**直接落到 Session**，不得再走"合成报文 → 重新解析"的降级路径。见 §4.6 与 §8 D4a（定为 P0）。

#### 1.4.4 前端示例字段后端不识别

`web/ingest.html:77` 示例含 `"start_ttl": 64`，但 `probeFlow`（`server.go:770-789`）无该字段 → 静默忽略（PM 审查 P2-8）。v2 统一 schema 时一并处理。

### 1.5 前端与离线约束：`ingest.html` 在内网是"裸奔 HTML"

| # | 问题 | 证据 |
|---|---|---|
| E1 | **Tailwind CDN 外网依赖** | `web/ingest.html:7` `<script src="https://cdn.tailwindcss.com">`。全部 8 个页面同样问题（`about/domains/events/index/ingest/logs/whitelist/settings.html` 均为第 7 行）；`web/index.html:14-15` 另依赖 cytoscape + jspdf CDN |
| E2 | 无外网时页面**完全失去样式**，只剩无格式 HTML | 同上。README 声称"单二进制分发、embed.FS 内嵌"（`README.md:34`）与"内网部署"定位直接冲突 |
| E3 | 上传结果无可视化 | `ingest.html:96-108`：仅 toast + JSON 字符串 |
| E4 | 主动探测占位提示为 `/24`，而后端 `/24` 100% 失败 | `ingest.html:57` placeholder `192.168.1.0/24`；`internal/probe/scan.go:200-216` 在第 256 次触发 `256 > 255` 拒绝（PM 审查 P1-3） |
| E5 | 已有原生动画基础可复用 | `web/assets/layout.js:44-91` 背景拓扑连线 canvas 动画；`:109-116` toast 过渡 |

### 1.6 「自生长发现」现状：有循环，但没有"生长"

已有（且工作正常）的自动循环：

| 循环 | 周期 | 证据 |
|---|---|---|
| 会话 → 拓扑增量灌入 | 2s | `main.go:117-131` |
| 风险检测评估 | 30s | `main.go:132` + `internal/detect/detector.go:73` |
| 边老化灰度 | 1min | `main.go:97` + `topology/engine.go:489` |
| 开机自启抓包 | 启动时 | `main.go:135-146`（仅 `capture_enabled=true` 时） |

**缺口（决定"能不能脱离人"）：**

| # | 缺口 | 证据 | 后果 |
|---|---|---|---|
| F1 | **停止抓包不真正停止** | `server.go:959-973`：`ctx` 创建后 `_ = ctx`（`:973`），消费 goroutine 从不看 ctx，pcap handle 继续跑，status 却显示 Stopped | 状态欺骗；重复 start 泄漏 goroutine（P1-4） |
| F2 | 抓包**断流无重连** | `main.go:139-143` / `server.go:965-972`：channel 关闭后 goroutine 直接结束，无任何重连 | 网卡闪断 → 永久停止采集，页面还显示"运行中" |
| F3 | **重启＝拓扑归零** | 节点/边 CRUD 生产代码零调用（全仓 grep：`CreateNode/UpdateNode/CreateEdge/UpdateEdge` 仅出现在 `internal/store/sqlite_test.go:28/40/59/68`）；`main.go:70-75` 每次启动空引擎 | 自生长的"记忆"不存在，每次重启从零长（P0-2） |
| F4 | PCAP 必须人工上传 | 无目录监听、无定时扫描 | 离线场景仍需人 |
| F5 | 默认配置下三路接入**全关** | `config.go:16-17` `ProbeEnabled:false, CaptureEnabled:false`；`configs/config.yaml:2-3` | 首次部署后无任何自动发现，页面空白 |
| F6 | 未知出口学习期**不可见** | `detector.go:56` LearningPeriod=10min；`:111` `learning := now.Sub(rc.d.started) < rc.d.LearningPeriod` | 前 10 分钟不产出 unknown_egress 事件，用户以为"坏了" |

### 1.7 V1.0 审查报告 P0 整改状态核对（本次实读）

| P0 | 标题 | 状态 | 证据 |
|---|---|---|---|
| P0-1 | Detector 并发 map 写崩溃 | ✅ **已修复** | `internal/detect/detector.go:43-47` 新增 `mu sync.Mutex`（注释明确写"P0-1 修复"）；`:94-96` `Evaluate()` 入口 `d.mu.Lock()` 整轮串行化 |
| P0-2 | 拓扑不持久化 | ❌ **未修** | 见 F3；`sqlite.go:152/163/223/234` 的 node/edge CRUD 仍为零生产调用 |
| P0-3 | 保存配置清空 probe_token | ❌ **未修** | `server.go:1166-1168` 仍无条件接受空串（`if v, ok := strFrom(m,"probe_token"); ok { cfg.ProbeToken = v }`） |
| P0-4 | 写接口裸奔 / CORS `*` / Actor 硬编码 | ❌ **未修** | `config.go:28` `ListenAddr: ":8080"`（=0.0.0.0）；`server.go:117` `Access-Control-Allow-Origin: *`；`server.go:534/560/575/...` `Audit("api", ...)` 硬编码 |
| P0-5 | README 截图缺失 | ✅ **已修复** | `docs/screenshots/` 存在；`README.md:125-136` 已引用 |

**与本文档相关的 P1：P1-1（流式/限流）❌、P1-2（会话只增）❌、P1-4（抓包真停止）❌。** 三者均纳入 v2 交付（§8）。

---

## 2. 目标定义

### 2.1 v2 要解决的核心问题（一句话）

> **让"数据接入"从一个"上传按钮 + 5 个数字"，变成一个"能回答问题、能看得见、能自己长"的接入中枢。**

拆成三个可判定的产品目标：

| 目标 | 现状 | v2 目标 | 判定方式 |
|---|---|---|---|
| **G1 看得懂**：PCAP 导入后能回答"这包里有什么" | 只有 packets/sessions 两个数字 | 6 个分析维度（总览/协议/TOP N/时间轴/异常提示/明细） | 导入合成 PCAP 后，报告各维度数值可与 `testdata/pcapgen` 场景构造对齐 |
| **G2 管得住**：探针从"匿名 POST"变成"可注册、可观测、可重试" | 无状态、无回执、无离线检测 | 探针台账 + 状态机 + 批次幂等回执 | 停掉探针 → 90s 内页面显示 degraded、300s 内显示 offline |
| **G3 自己长**：部署后无人工干预持续发现 | 三个开关全关、重启失忆、断流不重连 | 自生长闭环（§3.3） | 配置一次 → 重启服务 → 拓扑自动恢复 → 断网恢复 → 采集自动续上 |

### 2.2 非目标（明确不做，防止范围蔓延）

- ❌ 不做 PCAP 内容检索/全文搜索/载荷导出（**载荷不出库**，合规）
- ❌ 不做实时流水的逐包存储（只存聚合后的会话，与 V1.0 一致）
- ❌ 不做多租户、不做数据隔离
- ❌ 不做探针的远程安装/升级/命令下发（探针仅单向上报）
- ❌ 不做 PCAP 的在线剪辑/合并/转换工具

### 2.3 「自生长发现」愿景的产品拆解

用户原话：「他是一个可以脱离人的一个系统，部署在系统中自生长发现」。

产品层面拆为四层能力，**缺一层则"自生长"不成立**：

| 层 | 能力 | 现状 | v2 动作 |
|---|---|---|---|
| **L1 自启** | 配置一次即开机自动开始被动采集，无需人点"开始" | 部分有（`main.go:135-146`），但默认全关 | 部署向导/首启引导把 `capture_enabled` 置为可被一键打开；**主动探测仍默认关** |
| **L2 自愈** | 异常中断（网卡闪断、抓包句柄失效）自动重连，无需人 | ❌ 无（F1/F2） | 抓包真停止 + 断流重连（退避重试） |
| **L3 记忆** | 重启后拓扑、会话、节点 ID 不丢，继续在此基础上生长 | ❌ 无（F3 / P0-2） | **强依赖 P0-2**，v2 只做 sessions 侧来源持久化；节点落库由 P0-2 专项交付 |
| **L4 编排** | 系统自己按节奏完成"采集→聚合→生长→打标签→老化"，人只看结果 | 有（2s/30s/1min 三条循环） | 补"可观测"：接入页展示三条循环心跳 + 学习期剩余 + 数据源健康度 |

**关键裁定：自生长 ≠ 自动扫描。**
自生长的范围严格限定为「**被动感知 + 自动重连 + 状态自愈 + 持久化记忆 + 自动编排**」。
**主动发包（ARP/ICMP/Traceroute）永不自动开启**，必须由人显式打开 `probe_enabled`，且打开动作写审计、页面显著提示。理由：主动发包改变网络状态，越出"只观察不干预"的红线，自动化它等于把合规开关交给程序。

---

## 3. 功能设计

### 3.1 PCAP 深度分析

#### 3.1.1 交互形态改造（关键决策）

**现状**：同步阻塞，返回即结束。
**v2**：**异步任务 + 轮询进度 + 报告拉取**。

```
[前端] POST /api/ingest/pcap  ──► 202 {job_id}
         │
         ├─ 流式落盘（不再 io.ReadAll）
         ├─ 后台 goroutine 解析 → 聚合 → 灌拓扑 → 评估
         │
[前端] GET /api/ingest/pcap/job/{id}  轮询（1s，进度条动画）
         │
         └─ status=done ──► GET .../report  ──► 渲染 6 维度分析
```

兼容策略：`?sync=1` 且文件 ≤32MB 时保留同步语义（返回体含 `analysis` 摘要），供 curl/E2E 脚本使用（`scripts/e2e.sh` 现有断言不受影响）。

#### 3.1.2 维度一：总览指标（Overview）

| 指标 | 字段 | 数据来源 | 计算口径 |
|---|---|---|---|
| 报文总数 | `packets` | 循环计数（`server.go:867-874` 已有 `packets++`） | 从 PacketSource 收到的 `PacketInfo` 条数 |
| 解析成功数 | `parsed_packets` | 同上 | 非 nil 的 `PacketInfo` 数（IP+TCP/UDP 才非 nil，`parser.go:60-62/94`） |
| 跳过报文数 | `skipped_packets` | 差值 | 非 IP/TCP/UDP（ARP/ICMP/其他）→ **明确不计入分析**，需文案说明 |
| 会话数 | `sessions` | `Aggregator.Finalize()` 长度（`parser.go:372`） | 五元组归一化去重（`model.go:85-92` 双向排序去重） |
| 总字节 | `bytes` / `bytes_up` / `bytes_down` | `PacketInfo.Length`、`Session.BytesUp/BytesDown` | **IP 层长度**，不含以太网帧头；`Length` 取自 `ip.Length`（`parser.go:50/56`），TCP 且 `ip.Length==0` 时回退 `len(payload)`（`parser.go:69-71`）。上下行按"首包五元组源=客户端"启发式切分（`parser.go:314-318`）→ **报告需标注"方向为启发式推断"** |
| 时间跨度 | `first_packet_at` / `last_packet_at` / `duration_sec` | `Session.FirstSeen/LastSeen` 极值 | 按**报文时间戳**（SPEC §10.2，`parser.go:323/366`），非墙钟时间 |
| 平均包长 | `avg_packet_bytes` | `bytes / parsed_packets` | — |
| 平均/峰值速率 | `avg_pps` / `peak_pps` | 时间桶（同 3.1.5） | `avg = parsed_packets / duration_sec`；`peak = max(桶内 packets / bucket_sec)` |
| 主机数 | `host_count` / `internal_host_count` / `external_host_count` | `PacketInfo.SrcIP/DstIP` 去重 | 内外网判定复用 `topology.IsPrivate()`（`engine.go:138`）。**按 IP 去重，不做 MAC 合并**（PCAP 通常单采集点，MAC 合并属拓扑层职责） |
| 传输层构成 | `tcp_packets` / `udp_packets` | `PacketInfo.Proto`（`parser.go:65/88`） | — |

#### 3.1.3 维度二：协议分布（Protocols）

| 子维度 | 数据来源 | 口径 |
|---|---|---|
| 传输层占比 `by_transport` | `PacketInfo.Proto` + `Length` | 同时给**报文数**与**字节数**两种口径及各自 `ratio` |
| TCP 标志分布 `tcp_flags` | `PacketInfo.TCPFlags`（`parser.go:72-83`：SYN=0x02 / ACK=0x10 / FIN=0x01 / RST=0x04，可组合） | 分别统计 SYN、SYN+ACK(0x12)、FIN、RST、纯 ACK 的报文数 |
| 目的端口 TOP N `top_dst_ports` | `PacketInfo.DstPort` + `Proto` | 按会话数降序取 TOP 10，附 packets/bytes |
| 源端口 TOP N `top_src_ports` | `PacketInfo.SrcPort` | 同上，TOP 10 |
| TLS 画像 `tls` | `Session.SNI` / `JA3` / `JA4`（`parser.go:352-354`） | `sni_count`（去重域名数）、`sessions_with_sni`、`top_sni`（TOP 10）、`top_ja3`、`top_ja4` |
| HTTP 画像 `http` | `Session.HTTPHost`（`parser.go:358-362`） | `host_count`、`top_hosts` TOP 10 |

**边界声明**：不做 DPI、不做应用层协议识别（HTTP 仅取 Host 头，TLS 仅取 ClientHello 元数据）。

#### 3.1.4 维度三：TOP N 会话（TopSessions）

- 排序键：`bytes_total = BytesUp + BytesDown` 降序，默认 N=20（`?top_n=` 可调，上限 100）
- 每条输出：`five_tuple`、`bytes_total/up/down`、`packets`、`duration_sec`、`first_seen`、`last_seen`、`sni`、`http_host`、`ja3`、`ja4`、`is_long_conn`、`heartbeat_interval_ms`、`closed`、`mac`、`start_ttl`
- 口径：`duration_sec = LastSeen - FirstSeen`（§10.2）；`is_long_conn` 由 `LongConnSeconds` 判定（`parser.go:366-368`，默认 3600，`config.go:26`）；心跳间隔由中位数稳健判定（`parser.go:378-394`）
- 附带 `direction_hint`：`"src_is_client" | "dst_is_client" | "unknown"`，来源即 `parser.go:314-318` 的启发式（首见报文的源侧视为客户端），**显式标注为推断结果**

#### 3.1.5 维度四：流量时间轴（Timeline）

- 桶宽自适应：`bucket = clamp(round(duration_sec / 200), 1, 300)`，并吸附到档位 `{1, 5, 10, 30, 60, 300}` 秒
- 每个桶输出：`t`（桶起点，RFC3339）、`packets`、`bytes`、`active_sessions`（该桶内有报文出现的会话数）
- 口径：桶区间**左闭右开**；空桶补 0（保证前端折线连续）；`active_sessions` 按会话 `[FirstSeen, LastSeen]` 与桶区间相交判定（**粗略**，仅用于观感，不用于任何判定）
- 前端：SVG/Canvas 自绘**堆叠面积图**（bytes）+ 折线（packets），支持 hover 显示桶详情；无外部图表库

#### 3.1.6 维度五：异常流量提示（Hints）—— 合规重点

**定位：只给"值得人工看一眼"的线索，不给结论。** 文案模板固定为「呈现 XX 特征，建议人工核查」，禁止出现"违规/攻击/入侵/异常外联"等定性词。

| code | 触发口径 | 数据来源 | 默认阈值 | 级别 |
|---|---|---|---|---|
| `rst_ratio_high` | `RST报文数 / TCP报文数 > 阈值` | `TCPFlags&0x04`（`parser.go:81-83`） | 5% | notice |
| `syn_without_ack` | `SYN数 > SYN-ACK数 × 倍数`，且 SYN 数 > 20 | `TCPFlags` 0x02 / 0x12 | 3× | notice |
| `long_conn_present` | `IsLongConn == true` 的会话数 > 0 | `Session.IsLongConn` | 0（存在即提示） | info |
| `heartbeat_present` | `HeartbeatIntervalMs > 0` 的会话数 > 0 | `Session.HeartbeatIntervalMs` | 0 | info |
| `tls_on_nonstandard_port` | 有 SNI 且 `DstPort ∉ {443, 8443}` | `Session.SNI` + `FiveTuple.DstPort` | — | info |
| `high_fanout_host` | 内网主机 1h 内对外 `(dst_ip:port)` 去重数 > 阈值 | 与 `evalUnknownEgress` 同源（`reverseproxy.go:90-109`） | 20（复用 `max(3×基线,20)`，导入场景基线取 0） | notice |
| `traffic_concentration` | 单会话字节 / 总字节 > 阈值 | TOP1 session | 50% | info |
| `timestamp_out_of_order` | 时间戳逆序报文比例 > 阈值 | `PacketInfo.Timestamp` 单调性 | 1% | info |
| `small_packet_flood` | 单主机小包（<100B）pps > 阈值 | `Length` + `SrcIP` | 待确认（建议 1000 pps，需实测标定） | notice |

**明确不做的 hint**（防红线越界）：端口扫描判定、漏洞/攻击特征匹配、违规外联判定、C2 通信判定、加密流量性质推断。

**明确不支持的分析**（受当前解析能力限制，需写明，不得假装支持）：
- ❌ 重传/乱序：**不支持**（`parser.go:63-85` 未解析 TCP seq/ack 号）。如需支持须新增 seq 追踪，列为 P2 待确认项。
- ❌ ARP/ICMP/非 IP 族协议统计：**不支持**（`parser.go:60-62/94` 直接返回 nil）。
- ❌ 应用时延/RTT：**待确认**（需 seq/ack 配对）。

#### 3.1.7 维度六：会话明细（SessionDetails）

- 数据源：**本次 job 的会话切片**。v2 为 `sessions` 表新增 `source`(`pcap|capture|probe`) 与 `job_id`/`probe_id` 列 + 索引（`sqlite.go:45-62` 建表改造），落库时随行写入 → 明细查询走 `WHERE source='pcap' AND job_id=?`
- 分页：`?limit=20&offset=0`（limit 上限 200）
- 过滤：`proto` / `src_ip` / `dst_ip` / `dst_port` / `sni`（模糊） / `has_sni` / `is_long_conn` / `has_heartbeat`
- 排序：`bytes` / `packets` / `duration` / `last_seen`，`?order=desc|asc`
- 返回 `total` 供前端分页器

> 这一维度同时解决 B1/B3：sessions 表从"死数据"变成"可查询资产"，且顺带为 P0-2 的重启恢复提供数据源（PM 审查 §P1-2 建议"变废为宝"）。

### 3.2 探针推送管理

#### 3.2.1 概念定义（消除术语歧义）

StarMap 当前代码中"探针"一词指代两种完全不同的东西，v2 必须区分：

| 术语 | 指代 | 证据 | v2 命名 |
|---|---|---|---|
| 远端探针 | 部署在内网主机上、向中心端**上报**数据的 agent | `POST /api/ingest/probe`（`server.go:677`）；`ProbeReport`（`ingest/probe.go:14`） | **Probe**（本文 §3.2 全部指此） |
| 主动探测 | 中心端**对外发包**的 ARP/ICMP/Traceroute | `internal/probe/scan.go:76-108`；`POST /api/probe/trigger`（`server.go:1004`） | **Scanner / 主动探测**（不纳入自生长自动编排） |

#### 3.2.2 新增数据模型

```sql
-- 探针台账（新增表）
CREATE TABLE IF NOT EXISTS probes (
  probe_id       TEXT PRIMARY KEY,
  status         TEXT NOT NULL DEFAULT 'online',   -- online|degraded|offline|disabled
  status_since   DATETIME NOT NULL,
  first_seen_at  DATETIME NOT NULL,
  last_seen_at   DATETIME NOT NULL,
  last_batch_id  TEXT NOT NULL DEFAULT '',
  source_ip      TEXT NOT NULL DEFAULT '',
  hostname       TEXT NOT NULL DEFAULT '',
  agent_version  TEXT NOT NULL DEFAULT '',
  batches_total  INTEGER NOT NULL DEFAULT 0,
  packets_total  INTEGER NOT NULL DEFAULT 0,
  sessions_total INTEGER NOT NULL DEFAULT 0,
  avg_interval_sec INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_probes_status ON probes(status);

-- 推送批次（新增表）
CREATE TABLE IF NOT EXISTS probe_batches (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id     TEXT NOT NULL,
  probe_id     TEXT NOT NULL,
  status       TEXT NOT NULL,            -- accepted|partial|rejected|failed|duplicate
  received_at  DATETIME NOT NULL,
  packets      INTEGER NOT NULL DEFAULT 0,
  flows        INTEGER NOT NULL DEFAULT 0,
  accepted     INTEGER NOT NULL DEFAULT 0,
  dropped      INTEGER NOT NULL DEFAULT 0,
  sessions     INTEGER NOT NULL DEFAULT 0,
  new_events   INTEGER NOT NULL DEFAULT 0,
  error        TEXT NOT NULL DEFAULT '',
  UNIQUE(probe_id, batch_id)
);
CREATE INDEX IF NOT EXISTS idx_batches_probe ON probe_batches(probe_id, id DESC);

-- sessions 表新增列（改造 sqlite.go:45-62）
ALTER TABLE sessions ADD COLUMN source   TEXT NOT NULL DEFAULT 'pcap';   -- pcap|capture|probe
ALTER TABLE sessions ADD COLUMN ref_id   TEXT NOT NULL DEFAULT '';       -- job_id 或 probe_id
ALTER TABLE sessions ADD COLUMN batch_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source, ref_id);
```

> SQLite 的 `ALTER TABLE ADD COLUMN` 需带默认值；存量库升级走 `store.Open()` 中的轻量迁移（`sqlite.go:105-121` 增加 `migrate()` 步骤，用 `PRAGMA table_info` 判断列是否存在）。

#### 3.2.3 探针状态机

```
                      首次上报（auto_register=true，默认开）
        (未注册) ─────────────────────────────────────────► online ◄──┐
                                                              │       │
                         收到任意上报 / heartbeat             │       │
                    ┌─────────────────────────────────────────┘       │
                    │  （刷新 last_seen_at，status_since=now）         │
                    ▼                                                  │
                 online ──── now - last_seen_at > degraded_after ───► degraded
                    ▲            （默认 90s）                            │
                    │                                                   │
                    │            now - last_seen_at > offline_after     │
                    │            （默认 300s）                           ▼
                    │                                                offline
                    │                                                   │
                    └──────────── 收到上报（复活，写审计） ◄──────────────┘

   任意状态 ── 管理员 POST /api/ingest/probes/{id}/status {"status":"disabled"} ──► disabled
   disabled ── POST ... {"status":"enabled"} ──► offline（等下次上报自然升 online）
   disabled 状态下收到上报 ──► 403 rejected（批次记为 rejected，reason=probe_disabled）
```

**状态迁移规则：**
- 迁移由后台 goroutine 每 **15s** 扫描一次（新增，挂 `main.go` 的 ctx）
- 每次迁移写审计：`Audit("system", "probe_status_change", probe_id, "online->degraded")`（复用 `review.go:138` `Audit`）
- 参数配置化（新增 `SystemConfig` 字段）：`probe_degraded_after_sec=90`、`probe_offline_after_sec=300`、`probe_auto_register=true`、`probe_max_packets_per_batch=5000`
- **降级/离线只是状态标签，不触发任何动作、不下发指令、不告警外发**

#### 3.2.4 批次状态机与幂等回执

```
  收到 POST /api/ingest/probe
        │
        ├─ token 校验失败 ─────────────► rejected (401)
        ├─ probe 已 disabled ──────────► rejected (403, reason=probe_disabled)
        ├─ body > 64MB / JSON 解析失败 ─► rejected (413 / 400)
        ├─ 缺 probe_id ────────────────► rejected (400)
        │
        ▼
   received
        │
        ├─ UNIQUE(probe_id, batch_id) 冲突 ──► duplicate (200)
        │      返回首次处理结果的 accepted/sessions，不重复计数
        │
        ▼
   accepted  (dropped == 0)
        │
        ├─ 部分条目字段非法（缺 src_ip / 非法端口）被跳过 ──► partial (200, dropped>0)
        │
        ├─ 处理中 DB 错误 / panic ──────────────────────────► failed (500, 探针应重传)
        ▼
     终态（写入 probe_batches）
```

**探针侧重试约定（写入前端"接入说明"）：**
- 网络超时或收到 5xx → 用**同一 `batch_id`** 指数退避重传（1s/2s/4s/8s/16s，最多 5 次）
- 收到 4xx（除 429）→ **不重试**（属请求本身错误）
- 收到 429 → 按 `Retry-After` 重试
- 服务端保证 `(probe_id, batch_id)` 幂等 → 重传不会重复计数

**`batch_id` 生成建议**：`{probe_id}-{单调序号}` 或 UUID；缺失时服务端用 `sha256(body)[:16]` 兜底（保证重传同 body 仍幂等）。

#### 3.2.5 心跳

- **隐式心跳（主）**：任何一次成功上报即刷新 `last_seen_at`
- **显式心跳（辅）**：`POST /api/ingest/probe/heartbeat`，用于"无流量但探针存活"的场景（夜间内网静默期），避免误判离线
- 响应携带 `next_expected_at = now + degraded_after_sec`，探针可据此对齐上报节奏

#### 3.2.6 【P0 修复】探针上报字段不再被丢弃（D4a）

改造点：`server.go:741-754` 的 flows 处理分支
- **删除** `probeFlow.toPackets()` 合成报文路径（`server.go:792-836`）——它必然丢失 Payload 级特征
- **新增** `mergeReportedSession(f *probeFlow, baseTs time.Time) *model.Session`：直接构造 `model.Session`，把 `sni / http_host / ja3 / ja4 / is_long_conn / heartbeat_interval_ms / start_ttl` **原样落字段**，然后 `Aggregator.IngestSession(ses)`（Aggregator 新增方法，绕过 PacketInfo→Session 的重建）
- `packets[]` 原始报文仍走既有 `Aggregator.Ingest(p)` 路径（该路径本就能解析 Payload）
- 验收：用携带 `ja3`/`sni` 的探针上报构造用例，断言 `frp`/`clash` 规则可命中（当前必然不命中）

### 3.3 自生长发现

#### 3.3.1 能力清单

| 编号 | 能力 | 配置项 | 默认值 | 归属 |
|---|---|---|---|---|
| G-1 | 开机自动开始被动抓包 | `capture_enabled` | false（部署引导可开） | 已有 |
| G-2 | 抓包真停止 | — | — | **v2 修复（P1-4）** |
| G-3 | 抓包断流自动重连（退避 1s→2s→4s→…→30s 封顶，记 `restart_count`） | `auto_capture_restart` | true | **v2 新增** |
| G-4 | 会话→拓扑自动增量 | — | 2s | 已有 |
| G-5 | 自动检测打标签 | — | 30s | 已有 |
| G-6 | 自动老化灰度 | `aging_seconds` | 86400 / 1min 检查 | 已有 |
| G-7 | 重启后拓扑恢复 | — | — | **强依赖 P0-2（专项）** |
| G-8 | 探针随时接入、自动注册 | `probe_auto_register` | true | **v2 新增** |
| G-9 | 三路循环健康度可观测 | — | — | **v2 新增 `GET /api/ingest/sources`** |
| G-10 | 学习期剩余时间可见 | — | — | **v2 新增（数据源面板）** |
| — | ~~自动开启主动探测扫描~~ | — | — | **永久不做**（§2.3 裁定） |

#### 3.3.2 前端呈现

`ingest.html` 新增「自生长状态」卡：三条循环（采集 2s / 检测 30s / 老化 1min）各显示"上次心跳距今"，超时变灰；未知出口学习期显示倒计时；`topology_persisted` 为 false 时显示醒目提示「拓扑当前为内存态，重启将重建（P0-2 未启用）」。

---

## 4. API 契约（供开发直接实现）

> 约定：全部新增端点返回 `snake_case`；时间字段 RFC3339（SPEC §10.8）；错误体统一 `{"error":"..."}`。

### 4.1 `POST /api/ingest/pcap`（**改造**）

Request：`multipart/form-data`，字段 `file`；可选 query `?sync=1`

Response **202 Accepted**：
```json
{
  "job_id": "job-20261015-0001",
  "filename": "frp_tunnel.pcap",
  "size_bytes": 6482,
  "status": "queued",
  "queued_at": "2026-10-15T01:00:00Z",
  "poll_url": "/api/ingest/pcap/job/job-20261015-0001"
}
```

Response **200**（`?sync=1` 且 ≤32MB）：兼容 V1.0 结构 + `analysis` 摘要
```json
{
  "job_id": "job-20261015-0001",
  "filename": "frp_tunnel.pcap",
  "packets": 12000,
  "sessions": 87,
  "new_events": 2,
  "ingested_at": "2026-10-15T01:00:00Z",
  "analysis": { "overview": { "...": "见 §4.3" }, "hints_count": 3 }
}
```

错误：`400` 非 multipart / 坏魔数；`413` 超 200MB；`429` 并发导入数 ≥2（`ingestInFlight` 真正生效）

### 4.2 `GET /api/ingest/pcap/job/{job_id}`（**新增**）

```json
{
  "job_id": "job-20261015-0001",
  "filename": "frp_tunnel.pcap",
  "size_bytes": 6482,
  "status": "running",
  "phase": "parsing",
  "progress": 45,
  "counters": { "packets": 5400, "sessions": 61, "bytes": 1048576, "skipped": 20 },
  "started_at": "2026-10-15T01:00:00Z",
  "finished_at": "",
  "duration_ms": 1200,
  "error": ""
}
```
`status`：`queued|running|done|failed|canceled`；`phase`：`uploading|parsing|aggregating|detecting|done`。前端轮询 1s。

### 4.3 `GET /api/ingest/pcap/job/{job_id}/report`（**新增**）

Query：`?top_n=20&bucket=auto&limit=20&offset=0&order=bytes&proto=&sni=&is_long_conn=`

```json
{
  "job_id": "job-20261015-0001",
  "filename": "frp_tunnel.pcap",
  "size_bytes": 6482,
  "generated_at": "2026-10-15T01:01:00Z",
  "overview": {
    "packets": 12000, "parsed_packets": 11980, "skipped_packets": 20,
    "sessions": 87,
    "bytes": 1048576, "bytes_up": 400000, "bytes_down": 648576,
    "first_packet_at": "2026-10-15T00:00:00Z",
    "last_packet_at": "2026-10-15T01:00:00Z",
    "duration_sec": 3600,
    "avg_packet_bytes": 87.4, "avg_pps": 3.3, "peak_pps": 120,
    "host_count": 42, "internal_host_count": 30, "external_host_count": 12,
    "tcp_packets": 11000, "udp_packets": 980
  },
  "protocols": {
    "by_transport": [ { "proto": "tcp", "packets": 11000, "bytes": 900000, "ratio": 0.92 } ],
    "tcp_flags": [ { "flag": "SYN", "packets": 300 }, { "flag": "SYN_ACK", "packets": 290 },
                   { "flag": "RST", "packets": 600 }, { "flag": "FIN", "packets": 120 } ],
    "top_dst_ports": [ { "port": 443, "proto": "tcp", "packets": 5000, "bytes": 600000, "sessions": 30 } ],
    "top_src_ports": [ { "port": 52344, "proto": "tcp", "packets": 900, "bytes": 70000, "sessions": 1 } ],
    "tls":  { "sni_count": 12, "sessions_with_sni": 40,
              "top_sni": [ { "sni": "example.com", "sessions": 8 } ],
              "top_ja3": [ { "ja3": "769,47-53,...", "sessions": 5 } ],
              "top_ja4": [ { "ja4": "t13d1516h2_...", "sessions": 5 } ] },
    "http": { "host_count": 7, "top_hosts": [ { "host": "site.example.com", "sessions": 4 } ] }
  },
  "top_sessions": [
    { "five_tuple": { "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "src_port": 52344, "dst_port": 443, "proto": "tcp" },
      "bytes_total": 98321, "bytes_up": 1204, "bytes_down": 97117, "packets": 86,
      "duration_sec": 5400, "first_seen": "...", "last_seen": "...",
      "sni": "example.com", "http_host": "", "ja3": "...", "ja4": "t13d1516h2_...",
      "is_long_conn": true, "heartbeat_interval_ms": 30000, "closed": false,
      "mac": "aa:bb:cc:dd:ee:ff", "start_ttl": 64, "direction_hint": "src_is_client" }
  ],
  "timeline": {
    "bucket_sec": 10, "start": "2026-10-15T00:00:00Z", "end": "2026-10-15T01:00:00Z",
    "points": [ { "t": "2026-10-15T00:00:00Z", "packets": 30, "bytes": 2048, "active_sessions": 4 } ]
  },
  "hints": [
    { "code": "rst_ratio_high", "level": "notice",
      "title": "TCP 重置报文占比偏高",
      "detail": "RST 报文占 TCP 报文 5.5%，呈现连接频繁中断特征，建议人工核查（仅标签，非定性）",
      "metric": { "value": 0.055 }, "threshold": { "value": 0.05 },
      "related": [ "tcp/10.0.0.5:443" ] }
  ],
  "sessions_page": { "total": 87, "limit": 20, "offset": 0, "items": [ "同 top_sessions 结构" ] }
}
```

### 4.4 `GET /api/ingest/pcap/jobs`（**新增**）

Query `?limit=20&offset=0` → `{"total":5,"items":[{job_id,filename,size_bytes,status,packets,sessions,new_events,started_at,finished_at}]}`

### 4.5 `DELETE /api/ingest/pcap/job/{job_id}`（**新增**）

取消运行中的任务或删除历史记录 → `204 No Content`

### 4.6 `POST /api/ingest/probe`（**改造**）

Request：
```json
{
  "probe_id": "probe-office-01",
  "batch_id": "b-000123",
  "token": "可选（或 X-Probe-Token 头 / ?token=）",
  "sent_at": "2026-10-15T01:00:00Z",
  "ts": "2026-10-15T01:00:00Z",
  "probe_meta": { "hostname": "of-pc-01", "agent_version": "1.1.0", "ifaces": ["eth0"], "capture_mode": "pcap" },
  "packets": [ { "timestamp":"", "src_mac":"", "dst_mac":"", "src_ip":"", "dst_ip":"",
                 "src_port":0, "dst_port":0, "proto":"tcp", "ttl":64, "length":0,
                 "tcp_flags":2, "payload": "" } ],
  "flows": [ { "src_ip":"10.0.0.5","dst_ip":"203.0.113.9","src_port":52344,"dst_port":443,"proto":"tcp",
               "mac":"aa:bb:cc:dd:ee:ff","dst_mac":"","bytes_up":1204,"bytes_down":97117,"packets":86,
               "first_seen":"...","last_seen":"...","sni":"example.com","http_host":"",
               "ja3":"...","ja4":"t13d1516h2_...","is_long_conn":true,"heartbeat_interval_ms":30000,
               "start_ttl":64 } ]
}
```
> `start_ttl` 为 v2 新增识别字段（修复 P2-8：`ingest.html:77` 示例已有此字段但后端忽略）。

Response **200**：
```json
{
  "batch_id": "b-000123",
  "status": "accepted",
  "accepted": 120, "total": 120, "dropped": 0,
  "sessions": 34, "new_events": 2,
  "probe_status": "online",
  "server_time": "2026-10-15T01:00:00Z",
  "next_expected_at": "2026-10-15T01:01:30Z",
  "limits": { "max_packets_per_batch": 5000, "max_body_bytes": 67108864 }
}
```
`status` 取值：`accepted|partial|duplicate|rejected|failed`（对应 §3.2.4 状态机）。
错误：`401` token 失败；`403` probe disabled；`400` 缺 probe_id / JSON 错 / packets 与 flows 均空；`413` body 超限或单批次 packets 超限。

### 4.7 `POST /api/ingest/probe/heartbeat`（**新增**）

Request：`{"probe_id":"...","token":"...","sent_at":"...","stats":{"packets":0,"flows":0,"uptime_sec":3600}}`
Response：`{"probe_status":"online","server_time":"...","next_expected_at":"..."}`

### 4.8 `GET /api/ingest/probes`（**新增**）

Query `?status=online|degraded|offline|disabled`
```json
{ "total": 3, "items": [
  { "probe_id": "probe-office-01", "status": "online", "status_since": "...",
    "first_seen_at": "...", "last_seen_at": "...", "last_batch_id": "b-000123",
    "source_ip": "10.0.0.9", "hostname": "of-pc-01", "agent_version": "1.1.0",
    "batches_total": 1200, "packets_total": 1500000, "sessions_total": 34000,
    "avg_interval_sec": 30 } ] }
```

### 4.9 `GET /api/ingest/probes/{probe_id}`（**新增**）

```json
{ "probe": { "同上结构" },
  "recent_batches": [ { "batch_id":"b-000123","status":"accepted","received_at":"...","packets":120,"flows":0,"accepted":120,"dropped":0,"sessions":34,"new_events":2 } ],
  "stats_24h": { "batches": 2880, "packets": 3600000, "sessions": 81000, "new_events": 12 } }
```

### 4.10 `POST /api/ingest/probes/{probe_id}/status`（**新增**）

Request：`{"status":"disabled|enabled"}` → Response `200`：`{"probe_id":"...","status":"disabled","status_since":"..."}`
（写审计：`Audit(clientIP, "probe_disable"|"probe_enable", probe_id, "")`）

### 4.11 `GET /api/ingest/probes/{probe_id}/batches`（**新增**）

Query `?limit=50&offset=0&status=` → `{"total":1200,"items":[{batch 结构}]}`

### 4.12 `GET /api/ingest/batches/{batch_id}`（**新增**）

单批次详情（含 `error` 字段），排障用。

### 4.13 `GET /api/ingest/sources`（**新增**）

```json
{
  "generated_at": "2026-10-15T01:00:00Z",
  "capture": { "available": true, "running": false, "interfaces": ["eth0"],
               "packets": 0, "restart_count": 0, "last_packet_at": "" },
  "pcap":    { "jobs_total": 5, "jobs_running": 0, "last_import_at": "...", "packets_total": 60000 },
  "probe":   { "registered": 3, "online": 2, "degraded": 1, "offline": 0, "disabled": 0,
               "batches_total": 1200, "packets_total": 1500000 },
  "growth":  { "auto_capture_restart": true, "auto_detect": true, "auto_aging": true,
               "auto_probe_scan": false,
               "learning": { "active": true, "remaining_sec": 420, "started_at": "..." },
               "topology_persisted": false }
}
```

### 4.14 `POST /api/capture/stop`（**修复 P1-4**）

行为变更：真正关闭 pcap handle 并终止消费 goroutine（`server.go:978-989` 内 `_ = ctx` 处改造；`ingest.StartCapture` 增加 stop channel / CloseFn）。返回不变。

### 4.15 `GET /api/capture/status`（**扩展**）

在现有 `Running/Interfaces/Packets/Available`（`server.go:994-999`）基础上增加：`started_at`、`last_packet_at`、`restart_count`、`dropped`（若 libpcap 可获取）、`auto_restart`。

---

## 5. 前端交互（`web/ingest.html` 改造）

### 5.1 硬约束落地

- **删除 `web/ingest.html:7` 的 Tailwind CDN**。新增 `web/assets/theme.css`（本地，embed.FS 内嵌），以 CSS 变量 + 工具类复刻当前配色：`--bg:#0F172A`、`--card:#1E293B`、`--accent:#38BDF8`、`--text:#E2E8F0`、`--risk-high:#F87171`、`--risk-mid:#FB923C`、`--risk-low:#4ADE80`（与 SPEC §7 一致）。
- 图表：新增 `web/assets/chart.js`，**原生 SVG/Canvas 自绘**（环形占比、横向条形、堆叠面积时间轴），≤200 行，无外部依赖。
- 8 个页面统一改引本地 `theme.css` —— 属第 1 项 UI 重构的公共底座，**本文档声明此依赖**。

### 5.2 信息架构（单页 4 区，Tab 切换）

```
┌──────────────────────────────────────────────────────────────┐
│ 数据接入                        [刷新] [数据源总览] ← 按钮全在上方 │
├──────────────────────────────────────────────────────────────┤
│ [PCAP 深度分析] [实时抓包] [探针推送管理] [自生长状态]            │
├──────────────────────────────────────────────────────────────┤
│ Tab1 PCAP 深度分析                                             │
│  ┌─ 上传区（拖拽/选择，进度条，实时 packets/sessions 计数）──┐   │
│  ├─ 总览指标卡（8 格）                                       │   │
│  ├─ 协议分布（环形 TCP/UDP + 端口 TOP10 条形 + TLS/HTTP 榜） │   │
│  ├─ 流量时间轴（SVG 面积图，hover 显示桶详情）               │   │
│  ├─ 异常流量提示（卡片列表，按 notice/info 分组，文案带"建议人工核查"）│
│  ├─ TOP N 会话（表格，可排序）                                │   │
│  └─ 会话明细（筛选条 + 分页表格）  [导出 JSON] ← 表上方       │   │
├──────────────────────────────────────────────────────────────┤
│ Tab2 实时抓包：状态卡 + [开始][停止][刷新]（按钮全在区块右上）    │
│ Tab3 探针推送管理：探针台账表 + 批次表 + [启用/停用] + 接入示例 │
│ Tab4 自生长状态：三条循环心跳 + 学习期倒计时 + 持久化提示        │
└──────────────────────────────────────────────────────────────┘
```

### 5.3 关键交互

| 场景 | 交互 |
|---|---|
| 上传 | 选/拖文件 → 立即发 POST → 202 返回 job_id → 进度条动画（0→100，phase 文案逐段变化）→ done 后 300ms 淡入切换为分析报告 |
| 轮询 | `setInterval` 1s 请求 `/job/{id}`；页面 `document.hidden` 时暂停（沿用 `ingest.html:146-148` 的可见性判断） |
| 报告渲染 | 卡片入场：逐格 `translateY(8px)+opacity 0 → 0+1`，间隔 40ms（stagger） |
| 时间轴 | SVG path 绘制动画：`stroke-dasharray` 从 0 到全长，600ms ease-out |
| 表格排序 | 点击表头切换升/降序，箭头图标旋转过渡 180ms |
| 明细筛选 | 输入防抖 300ms，重新请求；表格行 `opacity` 淡出→淡入，避免闪烁 |
| 探针状态 | 状态徽标带呼吸动画（online 绿点 `pulse 2s`，degraded 橙点，offline 灰点，disabled 空心） |
| 离线检测 | 探针卡在 degraded/offline 时展示"距上次上报 3 分 20 秒"实时走秒 |
| Tab 切换 | 底部指示条滑动 + 内容区淡入（200ms），无第三方动画库 |
| 错误 | 沿用 `layout.js:128-134` `UI.errorHTML`；上传失败保留文件选择态，支持直接重试 |

### 5.4 UI 标准落地（对应用户第 1 项要求）

- **按钮位置统一**：所有区块的主操作按钮统一置于**区块右上角的 header 行**（上传区除外——拖拽区本身即主操作）；表格相关的功能按钮（导出/筛选/重置）统一置于**表格上方工具条**。**禁止**在内容中部或卡片底部散落按钮。
- **原生桌面质感**：1px 边框 + 低饱和背景 + 12px 圆角 + 紧凑 8px 栅格；hover 仅改边框/文字色，不用大色块；禁用态 `opacity:.4 + cursor:not-allowed`（沿用 `ingest.html:136-137` 做法）。
- **动画去 AI 感**：动效时长统一 160–240ms（交互反馈）/ 400–600ms（入场与图表绘制），缓动统一 `cubic-bezier(.2,.8,.2,1)`；禁止弹跳、禁止无限旋转加载以外的循环动画。

---

## 6. 验收标准

| # | 验收项 | 验证方式 |
|---|---|---|
| AC-1 | 上传 200MB 以内 PCAP，进程堆内存峰值 ≤ 文件大小 ×1.2 | `pcapfile.go:85` 改为流式后，用 100MB 样本 + `runtime.MemStats` 采样（**待实测标定基线**） |
| AC-2 | 并发第 3 个上传请求返回 429 | `ingestInFlight` 限流生效（当前 `:864-865` 只加不读） |
| AC-3 | 上传后立即返回 job_id，页面 1s 内出现进度条 | 手工 + E2E 断言 202 与 `job_id` 非空 |
| AC-4 | 报告 6 维度齐全且数值自洽 | `overview.bytes == Σ timeline.points.bytes`；`overview.packets == parsed_packets + skipped_packets`；`Σ by_transport.packets == parsed_packets` |
| AC-5 | 报告数值与合成场景可对齐 | 用 `testdata/out/frp_tunnel.pcap`（`testdata/pcapgen/pcapgen.go:215`）导入，断言 `top_sessions[0].ja4` 前缀为 `t13d1516h2`（Go-TLS 指纹，见 `pcapgen.go:86-108`） |
| AC-6 | hints 文案无任何定性词 | 全文检查 `hints[].title/detail` 不含"违规/攻击/入侵/违法/外联违规" |
| AC-7 | 会话明细分页 + 过滤 + 排序可用 | `?proto=tcp&is_long_conn=true&order=bytes&limit=20&offset=20` 返回结果正确 |
| AC-8 | sessions 表带来源 | 导入后 `SELECT DISTINCT source, ref_id FROM sessions` 出现本次 job |
| AC-9 | 探针首次上报自动注册 | 新 probe_id 上报 → `GET /api/ingest/probes` 出现该探针且 `status=online` |
| AC-10 | 停掉探针 → 90s 内 degraded，300s 内 offline | 手工/集成测试（后台 15s 扫描） |
| AC-11 | 探针恢复上报 → 状态回 online，审计有记录 | `GET /api/audit` 含 `probe_status_change` |
| AC-12 | 同 batch_id 重传不重复计数 | 连发 3 次同 body，第 2/3 次 `status=duplicate`，`probes.batches_total` 只 +1，`accepted` 与首次一致 |
| AC-13 | 禁用探针后上报返回 403 | `POST /status {"status":"disabled"}` 后再上报 → 403 + `reason=probe_disabled` |
| AC-14 | **探针上报的 JA3/JA4/SNI 不再丢失** | 上报带 `ja3`/`ja4`/`sni`/`heartbeat_interval_ms` 的 flow → 查询会话该字段非空 → 构造用例断言 `frp` 规则可命中（当前必不命中） |
| AC-15 | 抓包 stop 真正停止 | `POST /api/capture/stop` 后 `GET /api/capture/status` `Running=false` **且** `packets` 停止增长 |
| AC-16 | 抓包断流自动重连 | 模拟网卡 down/up（或 kill 句柄）→ `restart_count` 递增，采集恢复（**测试环境待确认**） |
| AC-17 | 页面在断网环境完整可用 | 断外网后访问 `ingest.html`，样式、图表、动画全部正常；浏览器 Network 面板**零外部域名请求** |
| AC-18 | 无 CDN 引用 | `grep -rn "https://" web/` 除注释外无结果 |
| AC-19 | 按钮位置统一 | 目视检查：所有区块主操作按钮在 header 行；无底部散落按钮 |
| AC-20 | 合规红线静态检查 | 全仓 grep 无"阻断/封禁/解密/外发/上报上级"相关实现；新增代码无 HTTP 出站调用 |
| AC-21 | `go build ./...` 与 `go vet ./...` 通过 | CI |
| AC-22 | `go test -race ./...` 通过（含新增并发用例） | CI（PM 审查 §3.2 要求） |
| AC-23 | E2E 脚本仍全绿 | `bash scripts/e2e.sh`（`?sync=1` 兼容路径） |

---

## 7. 合规裁定：第 4 项「账号系统 + APSSO」与「不做登录/RBAC」红线的关系

### 7.1 裁定结论

> **结论：可以接入 APSSO 单点登录，但必须限定为「可选、可关、单档位、只做门卫」的外部身份源接入。这不违反红线，而是对红线表述的精确化。**

### 7.2 理由（四条）

1. **红线的本意是"不自建管控体系"，不是"不能有门"。**
   红线原文：`README.md:18`「不做登录/RBAC（仅留 middleware 接口位）」、`SPEC.md:6`「本期不做：登录/SSO/RBAC（仅留 middleware 接口位）」。其约束的是 **StarMap 自己长出一套用户/角色/权限模型并据此管控网络**。外接身份源只回答"谁能打开这个页面"，不产生任何网络侧动作，与"只打标签不做管控"不冲突。

2. **不做鉴权本身就是 V1.0 的 P0 级风险，SSO 是它的合规解法之一。**
   PM 审查 P0-4 明确：`PUT /api/config` 可被人远程打开主动探测、`POST /api/events/{id}/review` 可把高危事件一键标误报并自动加白 —— 攻击者永久隐身。审查建议的"最小鉴权护栏（admin_token / 反代 / CORS / Actor）"（`PM-REVIEW:185`）**方向正确但形态不足**：单令牌无法追溯到人，反代 Basic Auth 依赖运维手工配置。**OIDC 门卫 + 审计 Actor=真实身份** 是同一目标的更强形态。

3. **它提升而不是削弱合规可追溯性。**
   当前所有审计的 `Actor` 硬编码为 `"api"`（`server.go:534/560/575/634/655/670/759/879/974/987/1022/1182`）。接入身份源后 `Actor` 变为真实账号 —— 对"谁复核了这个事件、谁改了配置"的可追溯性从**无**变为**有**。安全产品的合规姿态因可追溯性增强而提高。

4. **"可选可关"保证内网单机场景不受损。**
   用户明确要求"也不是必须要用 SSO"。默认 `auth.mode = none`，与 V1.0 行为完全一致；不配置 APSSO 也能一键部署。

### 7.3 三条硬约束（缺一不可，违反即视为触碰红线）

| # | 约束 | 具体要求 |
|---|---|---|
| **K1** | **默认关闭（opt-in）** | `auth.mode = none \| token \| oidc`，**默认 `none`**。未配置时行为与 V1.0 逐字一致，不新增任何重定向、不阻断任何请求。 |
| **K2** | **只做门卫，不做权限模型** | 仅两档：`viewer`（只读）/ `operator`（可写）。**禁止**引入：角色层级、数据范围（按域/网段隔离可见性）、审批流、租户、用户自助管理 UI、组织架构同步。用户与角色**完全由 APSSO 侧维护**，StarMap 不建用户表。 |
| **K3** | **不影响检测与产出** | 登录态**只影响"能否调用 API"，不影响"检测什么、打什么标签"**。同一份数据在有无登录态下产出必须完全一致。禁止外发、禁止据登录态改变告警行为。 |

### 7.4 明确剔除（不得回补）

- ❌ StarMap 内置用户管理页面 / 用户增删改 / 密码重置
- ❌ 用户组、角色继承、权限矩阵配置界面
- ❌ 通过 SSO  group claim 映射数据可见范围（= 变相 RBAC）
- ❌ 登录态影响主动探测开关、白名单、复核等任何业务判定
- ❌ 会话/令牌同步给任何第三方系统

### 7.5 APSSO 接入形态（最小接口约束，实现细节另开文档）

| 项 | 约定 |
|---|---|
| 协议 | OIDC `authorization_code` + PKCE(S256) + `refresh_token` |
| 依赖 | 优先 `golang.org/x/oauth2`（Go 官方系，纯 Go）；若实验室有统一 SDK 则优先用之 —— **待确认** |
| 配置 | `config.yaml` 新增 `auth: {mode, issuer, client_id, client_secret, redirect_url, scopes, role_claim, viewer_values, operator_values, session_ttl}`；**全部留空 = mode none** |
| 回调 | `GET /api/auth/oidc/callback`（`state`/`nonce` 校验，PKCE verifier 校验，ID Token 验签走 APSSO JWKS） |
| 会话 | HttpOnly + `SameSite=Lax` Cookie；内网 http 环境 `Secure=false`；本地签名，不引外部 session 库；`refresh_token` 轮换，服务端仅内存保存（**不落库明文**） |
| 端点 | `GET /api/auth/config`（返回 `mode` 与登录入口，供前端决定是否显示登录按钮）；`POST /api/auth/logout` |
| 降级 | APSSO 不可达 → 返回 503 + 页面提示"身份服务不可达"；**不允许**静默放行为已登录或匿名可写（防"故障即裸奔"） |
| 一键部署 | `scripts/deploy.sh` 增加可选参数/交互：`SSO_ISSUER / SSO_CLIENT_ID / SSO_CLIENT_SECRET / SSO_REDIRECT`；未填则写入 `auth.mode: none`，**不阻塞安装**（对应用户"一键部署但不是必须 SSO"） |
| 与 P0-4 关系 | `mode=oidc` 或 `mode=token` 启用时，P0-4 的"最小鉴权护栏"已满足；`mode=none` 时**仍必须**落地 P0-4 的其余项（默认监听 127.0.0.1、CORS 白名单、Actor=ClientIP） |

### 7.6 需同步修订的措辞（Action Item）

红线表述应从
> 「不做登录/RBAC（仅留 middleware 接口位）」

精确化为
> 「**不自建账号与权限体系、不做权限管控模型；可外接身份源（OIDC/APSSO）作为可选的单点登录门卫，默认关闭。**」

同步修订处：`README.md:18`、`SPEC.md:6`、`web/about.html`（合规声明）、`docs/PM-REVIEW-2026-10-14.md:5`（合规基线行）。
**在措辞修订完成前，第 4 项不得进入开发**，避免"实现已落地、红线文本仍写着不做"的合规不一致状态。

---

## 8. 优先级与排期

工作量口径：**S** ≤0.5 人日 · **M** 1–2 人日 · **L** 3–5 人日

### P0（本期必做；缺任一项则"数据接入 v2"不成立）

| # | 事项 | 对应问题 | 工作量 | 依赖 |
|---|---|---|---|---|
| **D1** | PCAP 导入异步化：`io.Copy` 流式落盘（改 `pcapfile.go:85`）+ job 任务模型 + 进度查询 + 并发限流（改 `server.go:864-865`）+ Server 超时（改 `main.go:168`） | A1-A5、P1-1 | **L** | — |
| **D2** | PCAP 分析报告：6 维度计算 + 新增 4 个报告端点 | A6、G1 | **L** | D1 |
| **D3** | `sessions` 表加 `source/ref_id/batch_id` + 索引 + 保留策略；`SaveSession` 改 upsert；删除退出时重复落盘（`main.go:188-191`） | B1-B5、P1-2 | **M** | — |
| **D4a** | **探针上报字段不丢弃**：删除 `toPackets` 合成路径，新增 `mergeReportedSession` + `Aggregator.IngestSession` | §1.4.3（P0 功能缺陷） | **M** | — |
| **D4b** | 探针台账 + 批次表 + 状态机 + 批次幂等回执 + 心跳端点 | C1-C6、G2 | **L** | D3 |
| **D5** | `web/ingest.html` 重构：去 CDN（新增 `theme.css`）+ 4 Tab 信息架构 + 自绘图表 + 动画 + 按钮位置统一 | E1-E3、G1/G2/G3 | **L** | D1/D2/D4 |
| **D6** | 抓包真停止 + 断流自动重连（P1-4 + F2） | F1、F2、P1-4 | **M** | — |
| **D7** | **P0-2 拓扑持久化**（自生长 L3 记忆层的强依赖） | F3、P0-2 | **L** | 跨模块专项，**并行推进** |
| **D8** | **P0-3/P0-4 最小鉴权护栏**（默认 127.0.0.1、CORS 白名单、Actor=ClientIP、空 token 不清空） | §1.7 | **M** | 与 §7 裁定衔接 |

> D7/D8 虽不属"数据接入"模块，但**D7 是自生长的硬前提、D8 是新增写端点（探针禁用/任务删除）的安全前提**，必须同期排期，否则 v2 上线即带病。

### P1（本期应当做）

| # | 事项 | 对应 | 工作量 |
|---|---|---|---|
| D9 | `GET /api/ingest/sources` 数据源总览 + 自生长状态面板（含学习期倒计时、`topology_persisted` 提示） | F6、G9、G10 | **M** |
| D10 | 探针显式心跳端点 + 页面离线倒计时 | §3.2.5 | **S** |
| D11 | 报告导出 JSON / CSV（仅元数据，不含载荷） | A7 | **S** |
| D12 | 导入任务取消（`DELETE /job/{id}`）+ 临时文件清理兜底 | A4 | **S** |
| D13 | pcapng 路径补齐单测（当前零测试） | A9、PM 审查 §3.2 | **S** |
| D14 | 修复 `/api/probe/trigger` 的 `/24` 目标（P1-3）+ `ingest.html:57` 占位文案 | E4 | **S** |
| D15 | 前端 XSS 事件委托改造（P1-6，ingest 页新增表格同样遵守） | P1-6 | **S** |

### P2（Backlog）

| # | 事项 | 工作量 |
|---|---|---|
| D16 | 删除死代码 `ingest/probe.go:23-44` 的 `ProbeHandler` 与 `server.go:134-152` 的 `probeTokenMiddleware` | **S** |
| D17 | 报告快照持久化 + 两次导入对比（"这次比上次多了什么"） | **M** |
| D18 | 大文件分片上传 / 断点续传 | **L** |
| D19 | TCP 重传与乱序统计（需新增 seq/ack 追踪，**待确认需求价值**） | **M** |
| D20 | 探针 agent 版本兼容提示与能力协商 | **S** |
| D21 | 时间轴刷选联动拓扑页（选中时段 → 拓扑只显示该时段活跃边） | **M** |

### 建议交付批次

| 批次 | 内容 | 可独立验收 |
|---|---|---|
| **B1** | D1 + D3 + D6 | 上传不再爆内存、抓包能真停（AC-1/2/3/15） |
| **B2** | D2 + D5（分析报告部分） | AC-4/5/6/7/8/17/18/19 |
| **B3** | D4a + D4b + D5（探针部分） | AC-9~AC-14（**含 P0 缺陷修复**） |
| **B4**（并行） | D7 + D8 | P0-2/P0-3/P0-4 关闭 |
| **B5** | D9~D15 | P1 收尾 |

**D4a 建议单独提前**：它是静默失效缺陷，修复成本仅 M，但影响 frp/clash/reverse_proxy 三条规则在探针场景的可用性，性价比最高。

---

## 9. 待确认项（严禁据此臆断实现）

| # | 待确认内容 | 影响 | 需谁确认 |
|---|---|---|---|
| Q1 | APSSO 的 OIDC 端点路径、JWKS 地址、是否提供 Go SDK | §7.5 实现方案 | 实验室身份服务负责人 |
| Q2 | APSSO 中用于区分 viewer/operator 的 claim 名称与取值 | §7.3 K2 | 同上 |
| Q3 | 内网是否为纯 http（决定 Cookie `Secure` 与回调 scheme） | §7.5 | 部署方 |
| Q4 | `small_packet_flood` 阈值需实测标定（当前无基线数据） | §3.1.6 | PO + 开发（用 `testdata/out/*.pcap` 采样） |
| Q5 | 200MB / 100MB 样本下的真实内存峰值与解析耗时基线 | AC-1 | 开发实测 |
| Q6 | 是否需要支持 pcapng 多接口（Interface Block）合并统计 | §3.1 | PO |
| Q7 | 探针 agent 是否已存在（实验室自研？开源？）—— 决定 `probe_meta` 字段与 `batch_id` 生成约定 | §3.2.4 / §4.6 | PO + 实验室 |
| Q8 | 抓包断流重连在目标 OS/网卡上的可测性 | AC-16 | 开发 |
| Q9 | `restart_count`/`dropped` 是否可从 libpcap 获取（需 `pcap.Stats()`） | §4.15 | 开发 |
| Q10 | 是否需要"导入目录监听"（定时扫描某目录自动导入新 PCAP）—— 属自生长 L4 的可选增强 | §3.3 | PO |

---

## 10. 附：本文档引用的关键代码位置索引

| 主题 | 位置 |
|---|---|
| PCAP 上传全量读内存 | `internal/ingest/pcapfile.go:85,89-98` |
| PCAP 上传同步处理 / 无分析产出 | `internal/api/server.go:841-888`（返回体 `:881-887`） |
| 上传上限 | `internal/api/server.go:32` |
| 全量会话重放 | `internal/api/server.go:891-911`（全库无任何 `CREATE INDEX`，grep 已核实） |
| sessions 表建表（无来源/无索引） | `internal/store/sqlite.go:45-62` |
| `ListSessions` 零生产调用 | `internal/store/sqlite.go:301`；仅 `sqlite_test.go:90` |
| 探针上报处理 | `internal/api/server.go:677-767` |
| **探针指纹丢弃（合成报文）** | `internal/api/server.go:792-836`（`mkPkt` `:808-819`） |
| `probeFlow` 携带指纹字段 | `internal/api/server.go:783-788` |
| FRP 三中二依赖 | `internal/detect/frp.go:64-66` |
| Clash 依赖 SNI | `internal/detect/clash.go:82-85` |
| 反代依赖 Host/SNI | `internal/detect/reverseproxy.go:25-27` |
| 死代码 ProbeHandler（含静默丢包） | `internal/ingest/probe.go:23-44`（丢弃 `:36-41`） |
| 未挂载的 token 中间件 | `internal/api/server.go:134-152` |
| 抓包停止不生效 | `internal/api/server.go:959-973`（`_ = ctx` 在 `:973`） |
| 已修复的 P0-1 并发锁 | `internal/detect/detector.go:43-47,94-96` |
| 未修的 P0-3/P0-4 | `internal/api/server.go:1166-1168`；`internal/config/config.go:28`；`server.go:117` |
| 会话永不淘汰 | `internal/parser/parser.go:372-399`；`internal/topology/engine.go:67`；`server.go:60` |
| 退出时重复落盘 | `cmd/starmap/main.go:188-191` |
| 三条自动循环 | `cmd/starmap/main.go:97,117-131,132`；`internal/detect/detector.go:73`；`topology/engine.go:489` |
| 开机自启抓包 | `cmd/starmap/main.go:135-146` |
| 学习期 | `internal/detect/detector.go:56,111` |
| 前端 CDN 依赖 | `web/ingest.html:7`（全部 8 页）；`web/index.html:14-15` |
| 上传结果 JSON 直出 | `web/ingest.html:103` |
| 探针示例含后端不识别字段 | `web/ingest.html:77` |
| `/24` 主动探测 100% 失败 | `internal/probe/scan.go:200-216` |
| 前端原生动画/工具基础 | `web/assets/layout.js:44-91,94-147` |

---

*文档结束。全部结论均附代码行号证据；无证据处已在 §9 显式标注「待确认」。*
