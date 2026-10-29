# 威胁情报对接指南（1.5.0）

面向**情报平台一侧的开发者**：怎么把结论推给 StarMap，怎么保证"重复推送时库里是新版本"，
以及推完之后怎么确认真的生效了。

StarMap 自己不需要看这份文档就能跑——它只是被动接收。这份文档是写给推送方的。

---

## 1. 两条通路，别混

| 通路 | 方向 | 触发者 | 鉴权 | 写本地库 |
|---|---|---|---|---|
| **推送** `POST /api/intel/push` | 情报平台 → StarMap | 平台定期推 / 事件驱动 | `X-Intel-Token` | 是 |
| **回源** `GET /api/nodes/{id}/ti` | StarMap → 情报 API | 运维人员点开某台机器 | `ti_api_key` | 是（带有效期） |
| 出图 `GET /api/topology` | — | 每次渲染拓扑 | — | 否，**只读本地库** |

三条原则，都是为了不出事：

1. **出图绝不回源。** 打开一次拓扑就等于把整图地址批量发给外部系统。标红的依据必须已经在库里。
2. **推送是机器到机器，必须凭令牌。** 情报写的是"结论"——匿名可写意味着任何人都能把地址标黑（诬告）
   或标白（洗白）。这里刻意**不**沿用探针上报那种"未配令牌即放行"的宽松策略。
3. **回源是人工动作。** 只有人点开某台机器、或主动点"回源刷新"，才会往你的 API 发请求。

---

## 2. 服务端准备（一次性）

系统配置 → 威胁情报，或直接改 `config.yaml`：

```yaml
intel_push_token: "给情报平台用的共享令牌"   # 空 = 拒绝所有推送（403）
intel_retention_days: 90                    # 到期清理，0 = 不清理

# 回源（可选；不配则只能靠推送）
ti_enabled: true
ti_endpoint: "https://ti.example.com/api/v1/ip/{ip}"
ti_api_key: "回源用的 key"
ti_timeout_ms: 5000                         # 默认 5000
ti_cache_seconds: 3600                      # 回源结果在本地留多久，到期允许再问（默认 3600）
```

> `intel_push_token` 为空时推送接口返回 **403 并说明原因**，而不是"没配就放行"。
> 这是有意的：一个还没配令牌的实例，不应该能被任何知道地址的人写结论。

令牌可以用 `openssl rand -hex 24` 生成，和情报平台各存一份。

---

## 3. 推送：最小可用示例

```bash
curl -sS -X POST 'http://starmap.internal:8080/api/intel/push' \
  -H 'Content-Type: application/json' \
  -H 'X-Intel-Token: 你的令牌' \
  -d '{
    "source": "my-ti",
    "records": [
      {"indicator":"203.0.113.10","verdict":"malicious","score":95,
       "tags":["c2","cobaltstrike"],"version":1042,"updated_at":"2026-10-28T10:00:00Z"},
      {"indicator":"198.51.100.7","verdict":"suspicious","score":60,
       "tags":["scanner"],"version":1042,"updated_at":"2026-10-28T10:00:00Z"},
      {"indicator":"192.0.2.55","verdict":"clean","score":0,"version":1042,
       "updated_at":"2026-10-28T10:00:00Z"}
    ]
  }'
```

响应：

```json
{
  "source": "my-ti",
  "stat": {"received":3,"inserted":2,"updated":1,"unchanged":0,"stale":0,"conflict":0,"invalid":0}
}
```

> 各计数取决于库里已有内容：同样的请求在空库上全是 `inserted`，在已有同版本数据上全是 `unchanged`。

### 3.1 请求体形态（四选一，按你平台的数据结构挑）

**A. 带包装（推荐）**

```json
{"source":"my-ti","verdict":"malicious","records":[...]}
```

`records` 也可以叫 `indicators` / `data` / `items`，取第一个非空的。
顶层 `source` 作为整批默认来源；顶层 `verdict` 作为整批默认判定。

**B. 裸数组**

```json
[{"indicator":"203.0.113.10","verdict":"malicious"}, ...]
```

**C. 纯文本 / CSV，每行一个指标**（适合从别的系统导出）

```bash
curl -X POST 'http://.../api/intel/push?verdict=malicious' \
  -H 'X-Intel-Token: 你的令牌' \
  --data-binary @blacklist.txt
```

```
# 支持逗号/制表符/分号分隔；第一列指标，第二列判定（可选），第三列分数（可选）
203.0.113.10,malicious,95
198.51.100.7,suspicious
badc2.example.com
```

> 纯文本模式`必须`带 `?verdict=` 或每行给判定，否则会 400——不知道是黑是白的指标入库没有意义。

**D. 单条**：直接推一个对象，等同于长度为 1 的数组。

### 3.2 字段别名表

你的平台不用改字段名，StarMap 认这些别名：

| 语义 | 接受的字段名（按优先级） |
|---|---|
| 指标 | `indicator` → `ip` → `value` → `ioc` → `host` |
| 判定 | `verdict` → `level` → `status`（顶层 `verdict` 亦可） |
| 分数 | `score` → `confidence`（0~100） |
| 标签 | `tags[]` → `tag`（字符串） |
| 版本 | `version` → `rev` |
| 结论时间 | `updated_at` → `updated` |
| 来源 | `source`（记录级优先于整批） |
| 原始记录 | `raw`（JSON 任意结构，原样存，排查"凭什么判黑"用） |

判定字段认中英文：`malicious`/`blacklist`/`botnet`/`恶意`/`黑名单` → `malicious`；
`suspicious`/`可疑` → `suspicious`；`clean`/`harmless`/`正常`/`白名单` → `clean`；
其他一律 `unknown`（有记录但判不出来，按"没情报"对待，不标红）。

时间字段接受 RFC3339、`2006-01-02 15:04:05`、Unix 秒、Unix 毫秒。

---

## 4. 覆盖语义（最重要的一节）

> 需求原话：「如果有重复数据，需要你即时覆盖到最新的版本」

**规则**：`version` 优先，其次 `updated_at`。只有满足下面任一条件才会写：

```
新记录的 version > 库里的 version
或：version 相等 且 新记录的 updated_at >= 库里的 updated_at
```

不满足就**拒收**，计入 `stale`（版本旧）或 `unchanged`（完全重复）。

### 4.1 为什么不是"后到覆盖先到"

"最后到的赢"听起来更省事，但它比较的是**网络顺序**，不是**时间顺序**。
重传、平台补推、双实例并发推、断网后批量补数据——任何一种都会让旧包晚于新包到达。
若无条件覆盖，一条三天前的推送就能把今天判定的"恶意"洗回"未知"。

这不是"脏数据"，是**结论被擦掉**，而且擦得无声无息：界面上那台机器悄悄从红变灰，
没人知道为什么。

### 4.2 六种结果的含义

| 字段 | 含义 | 你该做什么 |
|---|---|---|
| `inserted` | 本地原来没有，新增 | 正常 |
| `updated` | 本地有，本次版本更新，已覆盖 | 正常 |
| `unchanged` | 版本与时间都相同，幂等重推，未写 | 正常（说明你的重试逻辑在工作） |
| `stale` | **版本比库里旧**，已拒绝 | **要查**：时钟漂移？`version` 没单调递增？ |
| `conflict` | 版本与时间都相同、**结论不同**，已拒绝 | **要查**：改判定没升 `version` |
| `invalid` | 指标格式非法，已跳过 | 要查：数据源里混进了非地址字段 |

`stale > 0` 时响应会额外带一个 `warning` 字段：

```json
{"source":"my-ti","stat":{... ,"stale":1},
 "warning":"1 条比库里的版本旧，已拒绝（不会被覆盖）。请检查推送方的时钟或 version 是否单调递增。"}
```

`conflict > 0` 时带的是另一个字段，因为要修的地方不一样：

```json
{"source":"my-ti","stat":{... ,"conflict":1},
 "conflict_hint":"1 条的 version 与 updated_at 都和库里相同、但结论不同，已拒绝。同一个版本必须对应同一个结论：要改变判定请递增 version，否则等于允许无声改写已发布的情报。"}
```

**看到 HTTP 200 不代表全部生效。** 请务必读 `stat`、`warning` 和 `conflict_hint`——
服务端没有办法主动通知你"你推的是旧货"或"你在同版本下改了结论"，它只能在这里说一次。

### 4.3 同一版本必须对应同一结论（`conflict`）

`(version, updated_at)` 相同但 `verdict` 或 `score` 不同 → **拒绝**，计入 `conflict`。

为什么不像"后到覆盖先到"那样放行：那等于允许在不留痕的情况下改写已经发布的判定。
先推 `malicious` 再推 `clean`（版本号不变），事后从库里看不出哪一次是对的——
这正是最需要留痕的一类改动。反过来 `clean → malicious` 同理。

要改判定就**升 `version`**（这是唯一正确的做法，也天然留痕）。
如果你确实没有版本号体系，那就别把 `updated_at` 固定成同一个值——
让它反映"结论重新产出的时间"，改判时它会变。

### 4.4 版本号怎么给

- 有单调递增的版本号（批次号、自增 ID、ETag）就用 `version`，这是最稳的。
- 没有就用 `updated_at`（**必须是结论产出的时间，不是推送时间**）。
  用推送时间会让每次重推都"更新"，`stale` 保护形同虚设。
- 两个都不给：`version=0`、`updated_at=入库时刻`，此时等于是"后到覆盖先到"，
  乱序就洗白了。**能不给就尽量不要这么用。**

### 4.5 来源不会被空值抹掉

记录里没写 `source`、整批也没写，这条记录的来源就是空——但**不会覆盖库里已有的来源**。
一次不带 source 的重推，不该把"这条结论是谁给的"抹掉，否则统计里再也分不清谁给的。

---

## 5. 指标格式

| 写法 | 规范化结果 | 说明 |
|---|---|---|
| ` 203.0.113.10 ` | `203.0.113.10` | 去空格、引号 |
| `203.0.113.10/32` | `203.0.113.10` | `/32` 归一为单 IP |
| `203.0.113.0/24` | `203.0.113.0/24` | 保留网段，用于"整段情报" |
| `Evil.Example.COM` | `evil.example.com` | 域名小写 |
| `1.2.3` | **非法**（`invalid`） | 纯数字残缺点分，更可能是被截断的 IP |
| `fe80::1` / `10.0.0.1` | 合法 | 内网/链路本地**可以入库**（失陷主机场景） |

内网地址的边界要说清楚：

- **推送**：接受内网 IOC。"这台主机失陷了"的对象本来就在内网，这类数据只能从推送进来。
- **回源**：硬拦内网地址（返回 400 `ErrPrivateIP`）。公网情报源对内网地址只能编，
  返回的任何结论都是噪音，而且这一问本身就等于把内网结构报给了对方。

---

## 6. 容量与分批

- **单批上限 20000 条**，超过返回 `413`。
- 库是单连接（`SetMaxOpenConns(1)`），写入按 400 条一提交。一次几十万条会把它锁住几分钟，
  期间事件写入与拓扑快照全部排队，用户看到的是"界面卡住了"。
- 建议：常规增量推送每批几百到几千条就够；全量同步按 5000 条一批，批间留 100~200ms。
- 请求体上限 64MB（这条路由放宽过），超出返回 `413` 并提示分批。

---

## 7. 回源接口契约（你的 API 需要长这样）

StarMap 会 `GET` 你配置的 `ti_endpoint`：

```
https://ti.example.com/api/v1/ip/{ip}     ← 有 {ip} 占位则替换
https://ti.example.com/lookup             ← 没有则自动追加 ?ip=1.2.3.4
```

请求头：`Accept: application/json`，`ti_api_key` 非空时带 `Authorization: Bearer <key>`。

响应支持两种形态：

**扁平（推荐）**

```json
{"score":95,"verdict":"malicious","tags":["c2","cobaltstrike"],
 "source":"my-ti","link":"https://ti.example.com/report/203.0.113.10"}
```

**VirusTotal v3 风格**（也能吃）

```json
{"data":{"attributes":{"last_analysis_stats":{"malicious":40,"suspicious":5,
 "harmless":0,"undetected":15},"reputation":-20,"tags":["c2"]}}}
```

- `verdict` 缺失时按 `score` 折算：≥70 恶意，≥40 可疑，其余正常。
- 对端字段都会截断：标签最多 20 条、每条 40 字符（对端可控字段不能无限往界面塞）。
- 响应体读上限 1MB；**空响应体视为"无记录"**（`unknown`），不报错。
- HTTP 401/403 → "检查 API Key"；429 → 限流；其他 4xx/5xx → 记录错误但**不影响出图**
  （情报是增强信息，不该把整张拓扑拖挂）。

回源结果会写回本地库并带 `ti_cache_seconds` 有效期：到期前再点"查询情报"直接用本地，
点"回源刷新"（`?refresh=1`）会强制再问一次。**过期不等于删除**，未配回源时会照原样返回，
并明确标注"（数据已过有效期）"。

---

## 8. 推完之后怎么确认

```bash
# 库里现在有多少、判定分布、来源分布、最后入库时间
curl -sS http://starmap.internal:8080/api/intel/stats -b cookies.txt | jq

# 看某条记录到底存的什么（含 raw，排查"凭什么判黑"）
curl -sS 'http://starmap.internal:8080/api/intel?limit=20' -b cookies.txt | jq

# 直接看某台机器当前的情报结论（本地命中 / 回源）
curl -sS 'http://starmap.internal:8080/api/nodes/12/ti' -b cookies.txt | jq
```

`/api/intel/stats` 返回示例：

```json
{
  "total": 5,
  "by_verdict": {"clean": 2, "malicious": 1, "suspicious": 2},
  "sources": {"edr": 2, "my-ti": 3},
  "last_received_at": "2026-10-28T16:23:09Z",
  "oldest_updated_at": "2026-10-01T00:00:00Z",
  "push_token_set": true,
  "remote_enabled": false,
  "retention_days": 90
}
```

- `last_received_at` = 最近一次**入库墙钟**（不管你推的是哪天的结论）。
- `oldest_updated_at` = 库里最旧的**结论时间**。这个值长期不动，说明你的 `updated_at`
  根本没更新——推送在跑，数据是陈的。
- `remote_enabled=false` 表示没配回源，此时"查不到就是查不到"。

界面上：设置页「威胁情报」组有一张本地情报库概况卡片；拓扑详情面板的「安全核查」区
显示该节点的归属地 / 疑似隧道 / 情报结论 / 白名单，附「查询情报」「回源刷新」「加入白名单」。

---

## 9. 常见问题

**推了但图上没红？**
① 该地址有没有真的出现在拓扑里（没流量就没节点）；
② `verdict` 是不是 `unknown`（只有 `malicious`/`suspicious` 参与标红）；
③ 该节点是否已加白（白名单会压掉 `Highlight`，但不会改变情报结论本身）。

**反复推同一批，`updated` 一直涨？**
`updated_at` 用的是推送时刻而不是结论时刻。改成结论产出的时间，或者给 `version`。

**`stale` 一直大于 0？**
八成是时钟漂移，或者 `version` 每批都从 0 开始。检查一下生成版本号的那一侧。

**`conflict` 大于 0？**
同一个 `version` 下改了结论。改判定必须升 `version`（或让 `updated_at` 跟着变）；
否则等于要在不留痕的情况下改写已发布的情报，服务端会拒绝。

**同一个地址既有单 IP 记录又有网段记录，谁生效？**
出图时两种键都试（`203.0.113.0` 与 `203.0.113.0/24`），各自独立判断。
不保证"网段情报盖住单 IP"——那是策略问题，当前没有做优先级合成。

**能推域名吗？**
能存能查，但只有**能解析成 IP 的公网节点**才可能命中（拓扑上的是 IP）。
域名 IOC 目前主要用于人工排查，不参与自动标红。

**支持撤销吗？**
两种方式：推一条更高 `version` 的 `clean` 记录（推荐，留痕），
或 `DELETE /api/intel/{indicator}`（admin 权限，需登录）。
直接删库里就没了，"这条为什么被撤销"要靠审计日志查。

---

## 10. 已知边界

- 不做**关联分析**：同一个 C2 下的多台主机不会自动串成一个团伙视图。
- 不做**可信度加权**：两个来源互相矛盾时按 `version` 决胜负，不按来源信誉。
- 令牌是单值，不支持多平台分权（多个平台推送需共用令牌，审计里靠 `source` 区分）。
- 推送走 HTTP，跨不可信网段请套反代加 TLS。
- 没有"推送回执"回调：StarMap 不会主动告诉你的平台"这批里有 3 条过期"，
  只在那次 HTTP 响应里说一次。需要留证就自己记 `stat`。
