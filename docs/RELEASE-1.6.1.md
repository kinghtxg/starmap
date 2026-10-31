# StarMap 1.6.1 发布说明

> 主题：**"跑得久"和"报得准"是同一件事的两个面。**
> 发布日期：2026-11-01 · 上一个正式版：1.6.0

---

## 一、这一版在解决什么

1.6.0 补的是时间维度（任务账、变更视图、导出）。那之后做了一轮**不设终点的长跑压测**：
9 轮真实进程、每轮 4~8 分钟持续上报，规模从 3 万会话一路加到 9.5 万会话。

问题不是一个个冒出来的，是**四个一起冒出来并且互相掩护**：

```
规则误报 → 候选数 = 节点数 → 去重索引与写库跟着膨胀
        → 写锁被占满 → 探针上报变成秒级 → 现场只看到"服务变卡"
```

现场看到的是最后一步，根因在第一步。这一版把四个环节各自修掉，另外修掉一条
与压测无关、被 CI 抓出来的流量回退（见第二节第 1 条）。

**这一版没有新功能，也不改任何接口契约。** 唯一的语义变化是"一机两网"不再把
跨域访问判成接入（见下），这是修正误报，属于 bug fix。

---

## 二、修复

### 1. 五元组复用判据过松，同一条会话的流量会往回退

1.5.1 定的判据是 **FirstSeen 前移 + 累计值变小**。前半个条件挡不住误判：同一条会话
可能被**两个观察者**分别上报（本地抓包 + 探针、或两台探针），两边的 FirstSeen 天生
差几微秒到几秒，累计值也可能一边多一边少。旧判据会当成"同一条四元组上的新连接"整条复位：

| 位置 | 后果 |
|---|---|
| 聚合器（`parser.IngestAbs`） | 已累计的 10000 被打回 500，下游增量基准跟着退，等于凭空重算一遍流量 |
| 拓扑引擎（`topology.Engine.Ingest`） | `st.bytes` 清零后整条会话流量被重复计入，下一次上报又按旧值求差，数字来回跳且越跳越大 |

判据改为**时间上不重叠**：新快照的 `FirstSeen` 必须晚于旧会话的 `LastSeen`。
一个五元组在同一时刻只可能属于一条连接，所以这是物理判据而不是启发式——
真正的端口复用必然满足它，两个观察者看同一条会话必然不满足。

> 这条是 CI 抓出来的。本地 `-count=20` 一次没红，因为 Windows 的时钟粒度让相邻两次
> 夹具调用取到了同一个时间，判据缺陷被掩盖；一到纳秒精度的 Linux runner 上必挂。
> **硬件时钟粒度能掩盖判据缺陷，这类问题只能靠多平台 CI 复现。**

### 2. 多网融合规则把"访问过的域"当成"接入的域"

`evalMultiNet` 把会话**对端**所属网络域算进了本机。默认域 `gov=10.0.0.0/8`、
`office=172.16.0.0/12`，于是"10.x 访问 172.16.x"——政务网最普通的一条业务流量——
直接被判成一机两网 high。

- 4 万节点压测网络里一轮产出 **39,188 条 high**，占全量候选 **99.7%**；
- 改为只看**设备自有地址**（`n.IPs`），单地址设备入口即返回；
- 证据新增 `ips` 字段，复核时能直接看到这台机器挂了哪几个地址；
- 回归：`TestMultiNetIgnoresPeerDomains`（跨域访问不得报）+ `TestMultiNet`（自有地址跨域必须报）。

现场意义大于性能意义：值班的人被同一台机器的四万条 high 刷一周之后，就不再打开这个页面了。

### 3. 读被写堵死——连接池被限制成 1 条

`Open` 里是 `SetMaxOpenConns(1)`，理由是"SQLite 单写者"。单写者是对的，但 **WAL 下的读
不需要写锁**，限制成 1 条等于让全进程的读排在写事务后面：一条只返回 0 行的白名单查询
实测要等 **5.2 秒**才拿到连接。

- 连接池 32 条（`:memory:` 仍保持 1 条——每条连接是独立的内存库）；
- DSN 挂 `busy_timeout=10000`、`journal_mode=WAL`、`synchronous=NORMAL`、`_txlock=immediate`；
- `_txlock=immediate` 是关键：默认 DEFERRED 事务"先读后写"时锁升级失败会**立刻**返回
  `SQLITE_BUSY`（不理会 busy_timeout），表现为偶发写失败；
- 护栏 `TestReadNotBlockedByWriter` 是**双面**用例：默认池必须快（1ms），压回 1 条必须慢（191ms）。

### 4. 拓扑落盘每 2 秒重写整份工作集

`RunPersist` 把 `dirtyNodes`/`dirtyEdges`/会话增量基准每 2 秒全写一遍。问题在"脏"的定义：
探针每 5 秒重发同一条会话，于是"这条边又多了几个字节""这台机器的 last_seen 又新了"
永远成立。6 万节点 = **约 30k 行/秒**的持续写入，写锁被这一件事占满。

拆成两档：

| 档 | 内容 | 节奏 |
|---|---|---|
| 快通道 | 新节点、网卡/MAC/风险/标签变化、新边、在线状态切换 | 2 秒 |
| 慢通道 | `last_seen` 前进、边字节/包数累加、会话增量基准 | 60 秒 |

写失败时两档的脏集合都会放回重试。护栏：`TestSlowFlushSkipsCounterOnlyChanges`、
`TestFastFlushWritesNewEdges`、`TestFlushBatchSizeBoundedByChanges`。

### 5. 上报路径上三个 O(N) 写任务

一次上报原本是 4 个独立写事务，实测各段等待：

| 段 | 修复前 | 处理 |
|---|---|---|
| 资产全量同步 | 2,860ms | 上报触发改为 30 秒节奏（页面触发仍 5 秒）；`SyncAssetsFromNodes` 加 WHERE 守卫，无变化的行不产生页写 |
| 探针心跳 | 2,638~3,037ms | 按探针 1 分钟 TTL 节流（`last_seen` 分钟精度足够） |
| 上报审计 | 332~430ms | 同上节流——每秒十几条"上报了一条"没有信息量 |

### 6. 端口写入放大

每次上报都把这一批看到的端口 upsert 一遍（400 行 × 5 个索引）。端口是**资产台账**，
不是会话流水：按 `(ip,port,proto)` 做 3 分钟 TTL 节流，稳态写量降到 1/100 以下。
护栏：`TestFilterPortWritesThrottles`、`TestFilterPortWritesPrunesExpired`。

### 7. 去重索引不再读全表

`buildDedupIndex` 原来对 pending/confirmed 各查一次全表（13 列）。事件表没有保留期，
长期部署会一直长，于是"每轮评估读全表"= 评估耗时随运行时长线性劣化。
改为 `ListEventsForDedup`：窗口过滤下推 SQL，只取 5 个必要列。

### 8. 两处常驻的分段计时日志

- `[detect] 单轮评估偏慢`：copy / index / 六条规则（各自耗时与产出数）/ 白名单 / 去重 / 循环 / 写库；
- `[ingest] 单次上报偏慢`：flows / probe / topo（drain、engine、save、ports、assets）/ audit。

都只在超阈值时输出，正常路径零额外开销。这一版能在两轮内定位到真因，靠的就是它们。

---

## 三、复测数据（同一套喂数器，1.6.0 → 1.6.1）

| 指标 | 1.6.0 | 1.6.1 |
|---|---|---|
| 单轮评估（7 万会话） | 11.7s | **< 1s（无慢轮）** |
| 上报 p-max（极端 1400 新会话/秒） | 16.0s | **1.15s** |
| 上报 p-max（30 新会话/秒，贴近真实） | — | **无一条 > 500ms** |
| `/api/stats` | 5.8s | **324ms** |
| 事件表（4 万节点压测） | 94,692（99.7% 误报） | **0** |
| 拓扑节点数 | 116,467 | **655**（误报消失后恢复正常聚合） |

另有 3.2 万会话规模的真实探针节奏复测（探针 5 秒一轮、持续 10 分钟）：
上报 p95 **725ms**、读取 p95 **476ms**、零错误。

**怎么看这张表**：节点数从 11.6 万回到 655 不是因为"删了数据"，而是误报消失后
公网 /24 聚合恢复正常——之前每一台被误报的主机都被当成独立节点展开。

---

## 四、升级注意事项

1. **直接替换二进制即可**，无 schema 迁移。新增的 `discover_tasks` 表在 1.6.0 已建。
2. **连接池从 1 条变 32 条**（`:memory:` 仍为 1 条，因为每条连接是独立的内存库）。
   这个值是写死的（`internal/store/sqlite.go`），没有配置项。如果部署在内存极小的机器上
   （< 512MB），SQLite 每条约几百 KB 页缓存，32 条最多几十 MB，一般无碍。
3. **一机两网的事件会明显变少**。这是修误报，不是丢功能：跨域访问不再报，
   自有地址跨域（真双归属）照报。已有的事件不会被删除，历史记录仍在。
4. **落盘节奏变化**：进程被 `kill -9` 时，最多可能丢 60 秒的 `last_seen` / 边字节数更新；
   结构变化（新设备、新边）仍是最多 2 秒。优雅退出（`SIGTERM`）会补一次全量落盘，不丢。
5. **探针侧无需升级**，协议未变。

---

## 五、测试

| 项 | 结果 |
|---|---|
| `go test ./...` | 全绿（23 个包） |
| `go test -race ./...` | 全绿（CI 三平台：ubuntu / macOS / windows） |
| 合并覆盖率 | **76.0%**（门槛 72%） |
| `gofmt` / `go vet` / `staticcheck` | 零告警 |
| `govulncheck` | 零可达漏洞 |
| Fuzz 冒烟 | XFF 解析 30s / 台账 CSV 30s，无新崩溃 |

新增 / 加强的用例：

```
internal/parser/absflow_test.go            观察者时钟偏差不得复位（本次新增）
internal/api/port_throttle_test.go         端口写入 TTL 节流（首次/重复/过期/清理）
internal/api/ingest_latency_test.go        上报延迟不随规模线性增长
internal/store/concurrency_test.go         连接池并发安全（含"读不被写阻塞"双面断言）
internal/store/write_bench_test.go         写入路径单次成本
internal/topology/persist_cadence_test.go  快慢两档落盘的边界
internal/detect/eval_scale_test.go         误报修正后的规模基准
```

---

## 六、已知短板（未解决，不粉饰）

- **SQLite 单写者仍是上限**：1400 新会话/秒时 `SaveSessions` 会到秒级。再往上需要分库
  或换引擎，不是调参能解决的。
- **WAL 会长到几十 MB**：持续写入下有读快照长期存在，checkpoint 无法复位到起点。
  空间会复用，但文件不收缩。
- **任务进度不落库**：`discover_tasks` 只记开始/结束两个时刻，运行中的进度在内存里，
  进程重启后该任务记为「进程重启，任务中断」。这是有意的取舍，不是遗漏。
- **变更视图只覆盖端口**：资产新增/消失、事件变化还没有独立的变更流。
- **导出未异步化**：20 万行上限 + 并发名额 2，满额回 429 不排队。超大导出会占用一个
  HTTP 连接的整个生命周期。

---

## 七、文件清单

新增：

```
internal/api/port_throttle_test.go        端口写入节流护栏
internal/store/concurrency_test.go        连接池并发安全
internal/store/write_bench_test.go        写入路径单次成本
internal/topology/persist_cadence_test.go 快慢两档落盘
internal/api/race_on_test.go              -race 构建标记（api/detect/store 各一套）
internal/api/race_off_test.go
internal/detect/race_on_test.go
internal/detect/race_off_test.go
internal/store/race_on_test.go
internal/store/race_off_test.go
docs/RELEASE-1.6.1.md                     本文件
```

改动：

```
internal/version/version.go          1.6.0 → 1.6.1
internal/store/sqlite.go             连接池 32 条、DSN pragma、资产同步 WHERE 守卫
internal/topology/engine.go          落盘两档、五元组复位判据改为时间不重叠
internal/parser/absflow.go           五元组复位判据改为时间不重叠
internal/parser/absflow_test.go      夹具改为确定性锚点
internal/api/server.go               上报分段计时、资产/心跳/审计节流、端口写入节流
internal/detect/multinet.go          域维度只看自有地址
internal/api/intel.go                staticcheck 收口
internal/detect/detector.go          去重索引窗口下推
internal/detect/eval_scale_test.go   基准改为修正误报后的真实形态
internal/api/ingest_latency_test.go  -race 下跳过耗时预算
internal/store/changes_capacity_test.go 同上
README.md / CHANGELOG.md / SPEC.md   版本与叙述同步
```

---

## 八、怎么自己复现这一版的数字

```bash
# 1. 单轮评估成本（7 万会话）
go test ./internal/detect/ -run TestEvaluateCostAtScale -v

# 2. 上报延迟不随规模增长
go test ./internal/api/ -run TestProbeIngestLatencyDoesNotGrowWithState -v

# 3. 落盘节奏
go test ./internal/topology/ -run 'TestSlowFlush|TestFastFlush' -v

# 4. 端口写入节流
go test ./internal/api/ -run TestFilterPortWrites -v

# 5. 三平台并发正确性（本地无 gcc 时只能靠 CI）
go test -race ./...
```

压测本体没有进仓库（依赖真实探针节奏与长时间运行），但每个修复点都有对应的
规模基准用例，回归时跑上面五条即可。
