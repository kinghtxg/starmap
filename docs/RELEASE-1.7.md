# StarMap 1.7.0 发布说明

> 主题：**把"端点"重新组织成"业务系统"，同时先把底下的时间坐标调准。**
> 发布日期：2026-11-01 · 上一个正式版：1.6.1

---

## 一、这一版在解决什么

两条线，一前一后：

1. **正确性**——1.6.1 总结时明确留给 1.7 的短板：时间列在库里有两种时区表示，
   窗口查询的字符串比较会偏一个时区偏移。东八区的机器上偏 8 小时。
2. **能力面**——对齐灯塔（ARL）那类产品的资产主视图：站点。

顺序不是随意的。站点视图的核心字段全是时间派生的——"新增/失活"比的是
`first_seen` / `last_seen`，"证书还剩几天"比的是 `cert_expiry`。**底下坐标不准，
新页面会把老 bug 放大成看得见的错误**：查"最近 1 天新增的站点"会漏掉最近 8 小时。
所以先把坐标调准，再在上面加视图。

---

## 二、正确性：时间列 UTC 归一化

### 问题

`modernc.org/sqlite` 把 `time.Time` 落库成 `time.Time.String()`，**原样带着时区**：

```
"2026-11-01 13:03:52.7050173 +0800 CST m=+0.006953401"
```

同一瞬间在 `+0800 CST` 与 `+0000 UTC` 下是两串不同文本。所有窗口查询都是
`WHERE last_seen >= ?` 这样的**文本比较**——比的是"几点几分"，不是"哪个时刻"。

取证要看 `hex()` 或 `CAST(col AS TEXT)`：`Scan(&string)` 看到的是**读回时**
驱动的 RFC3339 归一化，不是库里的真实字节。**这一条不搞清楚，会误判成"没有问题"。**

### 修法：在写入口归一化，而不是逐个改 SQL

`internal/store/timeutc.go` 新增三层薄包装——`dbx` / `txx` / `stmtx`（分别嵌入
`*sql.DB` / `*sql.Tx` / `*sql.Stmt`），覆盖 `Exec` / `Query` / `QueryRow` /
`Begin` / `Prepare`，所有参数先过 `normArg`：

```go
type utcValue struct{ t time.Time }

// 刻意返回 string 而不是 time.Time，否则驱动又会调 .String() 把时区带回来
func (u utcValue) Value() (driver.Value, error) { return u.t.UTC().String(), nil }
```

选择"改写入口"而不是"改每个查询"的理由很直白：查询有一百多处，写入口只有三个；
而且改查询意味着旧库里的历史数据仍然不一致。

**`Prepare` 那一层必须覆盖。** 预编译语句的 `Exec(args ...any)` 签名不带 query
参数，绕过 `dbx.Exec` 就会让批量写入退回本地时区——这条是回归用例抓出来的，不是看代码看出来的：

```go
check("ports", "first_seen", "port=80")    // 单条 UpsertPort
check("ports", "first_seen", "port=81")    // 批量 UpsertPorts
check("sessions", "first_seen", "")        // 批量会话
```

> 现场表现是：站点列表的时间是 `2026-11-01T05:24:50Z`，变更视图里却是 `+08:00`。
> **同一条链路的两端不一致，通常说明中间有一条支路没被覆盖。**

### 存量迁移

13 张表 22 个时间列，按 **rowid 游标**每批 5000 推进，在 `meta` 表打
`schema.time_utc` 标记、只跑一次，失败不阻断启动（转换行数记在 `meta` 里）。

两个坑：

| 坑 | 后果 | 修法 |
|---|---|---|
| 分批"每批重查一遍过滤条件" | 解析不了的值永远满足 `NOT LIKE '%+0000 UTC'`，**原地打转成死循环** | 按 rowid 游标推进 |
| 幂等判断把 `ErrNoRows` 当成"meta 表不存在" | 第一次调用静默 `return 0`，一条都没转 | `switch` + `errors.Is(err, sql.ErrNoRows)` 分开判 |

用例 `TestNormalizeTimeColumnsMigratesLegacy` 绕开 `dbx` 用 `st.db.DB.Exec` 直写
`+0800 CST` 老格式、清掉标记、跑迁移，断言三件事：**时刻不变**、**能用 UTC 参数命中**、
**第二次无改动**。

---

## 三、新增：站点资产

前面所有表都是「某 IP 某端口」的端点视角。可运维的人要的数字是「网里有多少个 Web 站点、
哪个证书下周到期、哪个系统到现在没人认领」。

### 站点是派生视图，不建表

`(ip, port)` 聚合，`https`/`http` 由是否有证书情报判定。不建独立表是刻意的：
站点与端口是同一份事实的两种切法，存两份就要处理"重扫之后谁覆盖谁"，
而这种不一致从来不会自己消失。人工标注落独立的 `site_meta`，重扫不覆盖人的判断
（与 1.6.0「任务账只记账不复制扫描结果」同一理由）。

### 判据是「有 HTTP 层响应」，不是「有证书」

```sql
WHERE p.state = 'open' AND p.proto = 'tcp'
  AND (p.http_status > 0 OR p.title <> '' OR p.server <> '')
```

**这一条是被真机打回来的。** 最初按"有证书"判定，端到端跑出来一个
`https://127.0.0.1:3389` 的假站点——**RDP 的 3389 也会完成 TLS 握手并带回一张
`CN=机器名` 的自签证书**。按证书判定的话，每台 Windows 上都会凭空多出一个 https 站点。
单测里现在有「只有证书 → 不是站点」的分支，注释写明来自真机实测。

### 证书情报与风险标签

端口表新增 6 列：`server`、`http_status`、`http_location`、`cert_issuer`、
`cert_expiry`、`self_signed`。沿用"指纹列只能有则覆盖、不能被空值抹掉"的 UPSERT 口径
（`CASE WHEN excluded.x <> '' THEN … ELSE ports.x END`）——一次没取到证书，
不该把上次取到的抹掉。

标签：`cert_expired` / `cert_expiring`（≤30 天）/ `self_signed` / `untitled` / `plaintext`。

**有没有证书情报一律看 `cert_expiry` 是否为空**，不看「剩余天数 `-1`」——`-1` 同时是
「昨天到期」的合法答案，拿它当哨兵会把刚过期的证书整个漏掉：

```go
switch {
case site.CertExpiry == "":        // 没有证书情报，不参与证书风险评估
case site.CertDaysLeft < 0:        // 含 -1（昨天到期）：确实有证书且已过期
    risk = append(risk, "cert_expired")
case site.CertDaysLeft <= 30:
    risk = append(risk, "cert_expiring")
}
```

顺序颠倒（先判 `-1` 等于"无情报"）会出现两种错误同时发生：每个非 TLS 站点被标成
"证书已过期"，而刚过期一天的证书一条都不报。**告警里最响的那个标签一旦不准，
整块告警就都不可信了。**

### 性能：`GROUP BY` + 单 `max()` 聚合，不用窗口函数

SQLite 保证裸列取产生最大值的那一行，所以：

```sql
SELECT p.ip, p.port, MAX(p.last_seen) AS last_seen, p.title, ...
FROM ports p ... GROUP BY p.ip, p.port
```

比 `ROW_NUMBER() OVER (PARTITION BY ...)` 快一个档：

| 规模 | 窗口函数 | `GROUP BY` + `max()` |
|---|---|---|
| 10 万行端口 / 5 万站点 · 首页 | 410ms | **228ms** |
| 10 万行端口 / 5 万站点 · 统计 | 1.45s | **618ms** |
| 2 万行端口 / 1 万站点 · 首页 | 58ms | **29~69ms** |
| 2 万行端口 / 1 万站点 · 统计 | 137ms | 137ms |

绝对值随机器波动（同一台机器多次复测能从 29ms 到 69ms），**要看的是倍数不是绝对值**。

顺带把连接层的 PRAGMA 调对了。这几项默认值对"5 万行端口"这种库等于没配：

| PRAGMA | 默认 | 现在 | 理由 |
|---|---|---|---|
| `cache_size` | 2MB | 8MB | 默认页缓存对全表聚合等于没有 |
| `mmap_size` | 0 | 256MB | mmap 是**进程级共享**的，不像 cache_size 按连接计 |
| `temp_store` | 文件 | MEMORY | 站点视图的 GROUP BY / ORDER BY 临时 B 树别落盘 |

**这几项不会因为写错而报错**——SQLite 对不认识的 pragma 静默忽略，症状只是"页面莫名其妙地慢"。
所以补了 `TestPragmasEffective` 逐项读回实际生效值；`mmap_size` 硬比对 256MB，
因为它退回 0 时读放大问题会悄悄回来。

> 中途踩了一个：**CTE + 聚合会丢类型亲和性**，`Scan(&time.Time)` 报
> `unsupported Scan, storing driver.Value type string into type *time.Time`。
> 时间列只能按字符串读、自己解析。

### 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/sites` `/sites/stats` `/sites/tags` | 列表 · 统计 · 全部标签 |
| GET | `/api/sites/detail?key=https://ip:443` | 详情 + 同主机端口 |
| GET | `/api/sites/changes?days=7` | 窗口内新增 / 失活站点 |
| POST/DELETE | `/api/sites/meta` | 人工标注 |
| GET | `/api/export/sites.csv` | CSV（防公式注入 + BOM） |
| GET | `/api/report` | 单文件 HTML 报表 |

站点标识形如 `https://10.0.0.5:443`，含 `://` 和 `:`，**不能放进路径段**，
所以走查询参数 `?key=` 而不是 `/sites/{key}`。

POST 的请求体字段也叫 `key`，不叫 `site_key`。第一版写成 `site_key`，结果
同一个标识在 GET/DELETE 里是 `?key=`、在 POST body 里换了个名字——对接方发
`{"key": ...}` 会收到「站点标识格式错误: ""」，看起来像自己写错了。
**读写字段必须同名**，这条对任何要给别人对接的接口都成立。

标注写入前先校验站点真实存在（否则 404）——不然 `site_meta` 会变成任意字符串的垃圾桶。
标签 ≤20 个、单标签 ≤32 rune。

标注字段是**系统名 / 归属单位 / 标签 / 备注**。归属单位（`department`）刻意与台账 CSV
的字段同名——站点标注的主要用途就是「这个系统该找谁认领」，而台账里已经有这个概念，
换个名字会让人以为是两件事。

---

## 四、新增：单文件 HTML 报表

`/api/report` 输出三节：**证书风险**（即将到期 / 已过期）、**未标注站点**
（对应账外业务系统）、**窗口内站点变更**。零外链，浏览器直接 Ctrl+P 存 PDF。

用 `html/template` 而不是手拼字符串：报表会被下载、转发、用浏览器打开，
**受众往往不是管理员，XSS 面比后台页面更大**。

用例 `TestReportHTML` 把 `<script>alert('xss')</script>` 塞进页面标题、
`"><img src=x onerror=alert(1)>` 塞进产品名，断言输出里只出现转义形态
（`&lt;script&gt;` 出现、`<img src=x` 不出现）。

清单各限 50 条——**一份 2000 行的报表等于没有**。

---

## 五、测试与复测

### 门禁

| 项 | 结果 |
|---|---|
| `gofmt -l .` | 空 |
| `go vet ./...` | 空 |
| `staticcheck ./...` | 空 |
| `go test ./... -count=1` | 全绿（连跑两轮确认无偶发） |
| 全仓合并覆盖率 | **76.6%**（门槛 72%；1.6.1 为 78.1%） |
| `internal/store` | 73.8% · `internal/api` 74.9% · `internal/probe` 84.1% |

覆盖率比 1.6.1 低 1.5 个百分点，原因不是"测试变少了"，而是这一版新增了约 900 行
生产代码（站点派生视图 + 报表 + 时区包装层），分母变大了。**不为了让徽章好看去补无意义断言**——
新代码的实际覆盖是够的：`scanSite` / `CountSites` / `certDaysLeft` / `siteRisks` / `parseSiteKey`
都是 100%，`normalizeColumn` 81.5%，`dbx`/`txx`/`stmtx` 的每个方法都有直接用例。

### 真机端到端（Windows，`starmap.exe`，127.0.0.1 实扫）

```
/api/health                     {"status":"ok","version":"1.7.0"}
主动发现 quick 档 127.0.0.1      10 个开放端口 / 6 个指纹
/api/sites                      6 个站点
/api/sites/stats                {"total":6,"online":6,"untitled":2,
                                 "self_signed":1,"expiring":1,"expired":1}
https://127.0.0.1:8443          剩 19 天 · SAN 3 项 · 自签
https://127.0.0.1:10000         已过期 114 天 · DigiCert
/api/changes?days=1             11 条
/api/sites/changes?days=1       added 6
/api/export/sites.csv           BOM ef bb bf · 23 列中文表头
/api/report                     5995 字节 · 三节齐全
```

### 真实浏览器（Playwright + msedge）

站点资产页：6 行数据、4 张统计卡、详情抽屉可开、`errors: []`（无 JS 异常）。
四张卡片实测 `w=274`、排到 1142px，表格 `overflowX: 0`，无错位与截断。
**判断布局不靠肉眼截图**——缩放会把正常看成被裁，用 `getBoundingClientRect()` 实测。

### 压力测试（32 并发 × 25 秒，混合读写，含 `POST /api/sites/meta`）

```
成功 134466 · 失败 98（全部是客户端端口耗尽，非服务端） · RPS 5378.6
p50 5.6ms · p95 11.2ms · p99 15.0ms · max 71.5ms
```

> 第一版压测报了 17128 个 502，看着像服务端崩了，其实是压测客户端自己的问题：
> `urllib` 读了 `http_proxy` 环境变量，打 `127.0.0.1` 也走代理；而且它不复用连接，
> 把 Windows 客户端端口耗光（`WinError 10048`）。换成 `http.client` 每线程一条长连接后，
> p95 从 86.4ms 降到 11.2ms，RPS 从 352 升到 5378——**这些数字的差异全部来自客户端**。
> 压测报出来的第一个错，先怀疑压测器。

### 两条拿"总耗时"当断言的用例改成测量真正关心的指标

**① `TestPortChangesNarrowWindowFast`** 原来断言「5 万行 / 1 天窗口 < 80ms」。
1.7 给 ports 加了 6 个证书列，行宽从 17 列涨到 23 列，**首批读的 500 行要碰更多页**：
同一台机器同一份数据，1.6 行宽下 60~75ms，1.7 行宽下 71~98ms，断言开始靠运气过
（连跑三次：98.4 / 71.2 / 73.0ms）。

改法不是把数字调大就完事：

- **主守卫换成执行计划**——`EXPLAIN QUERY PLAN` 里不许出现 `SCAN ports`。
  「成本不随表总量增长」只有一个判据：优化器走索引定位。1.6.0 那次
  395ms → 40ms 的修复，本质就是把这个 `SCAN` 换成了 `SEARCH`。
- **绝对上界放到 150ms**，只防数量级跳变（ms → s）。

**② `TestMarkStalePortsScales`** 这条更糟——它的注释写着「守的不是总耗时，
而是**单次持锁时长**」，断言测的却是总耗时，**注释与断言互相矛盾**。
分块写入的总耗时 = 批数 × (更新成本 + 一次提交落盘)，落盘成本是磁盘的、不是代码的：
同一份代码空闲时 0.3s，与其他包并行跑时 3.07s 直接红。

改为读新增的 `stalePortStats` 逐批回调，直接判两件事：**批数必须与 5000 一批相符**
（防止退化成一条 `UPDATE` 打全表）、**任意单批耗时不超过上界**（防止单批变成大事务）。
实测单批最慢 212ms。

> 两条的共同点：**断言写的是"快不快"，要守的是"结构对不对"。**
> 快慢受磁盘、负载、行宽影响，会漂；结构不会。把预算调到刚好能过，
> 等于把断言变成随机数生成器——而随机失败的 CI，最后一定会被人加 `t.Skip`。

### 新增：包装层的直接用例

`internal/store/timeutc_test.go` 把 `dbx` / `txx` / `stmtx` 的**每个方法**各走一遍
（`Exec` / `Query` / `QueryRow` / `Prepare` × 连接与事务），逐行断言库里字节是
`+0000 UTC`，并覆盖 `sql.NamedArg` 递归、`*time.Time` 非 nil 与 nil、
以及 `normArgs` 的「无时间参数不复制切片」快路径。

为什么要专门测这层：`stmtx.QueryRow` 和 `dbx.QueryRow` 长得一模一样，
**"漏一个"靠读代码看不出来**。1.7.0 初版就是漏了 `Prepare`，单条写入是 UTC、
批量写入是本地时区，两种表示混回同一张表。

---

## 六、灯塔能力对标：到了什么、没做什么、为什么

这一节回答「想要的能力能不能达到」。结论先说：**资产测绘这条主线的核心能力已经到了；
漏洞验证与外部情报联动这两块，是刻意不做的，不是做不完。**

### 已经具备（对标 ARL 的主功能面）

| 能力 | StarMap 的实现 | 与 ARL 的差异 |
|---|---|---|
| 端口/服务识别 | 内置纯 Go 扫描 + 70 条指纹规则，优先认国产内网目标 | 不依赖 masscan/nmap（政务网运维机常装不上） |
| 站点指纹 | 站点视图：状态码 / Server / 标题 / 跳转 / 证书全字段 | 1.7 补齐 |
| 证书情报 | CN / SAN / 签发者 / 到期 / 剩余天数 / 自签 + 5 类标签 | 1.7 补齐 |
| 站点变更监控 | `/sites/changes` 窗口内新增 / 失活 | 1.7 补齐 |
| 资产分组与搜索 | 标签 + 归属单位 + 系统名（`site_meta`） | 1.7 补齐 |
| 定时任务 | 扫描窗口、失败退避、已知主机降频 | 更偏"能长期挂着"而非"跑一次" |
| 任务账 | `discover_tasks` 落库，重启不丢，可真取消 | 1.6.0 起 |
| 报表出口 | 单文件 HTML（Ctrl+P 存 PDF）+ 4 类 CSV | 无 PDF 生成依赖 |
| **被动测绘** | **PCAP / 抓包 / 探针三路 + 自生长拓扑 + XFF 七层还原** | **ARL 没有，这是 StarMap 的差异点** |
| **账实三方对照** | 台账导入 → 在册在网 / 台账外 / 僵尸 / IP 不符 | **ARL 没有** |

### 刻意不做（并且有理由）

| 能力 | 不做的理由 |
|---|---|
| nuclei PoC 漏洞扫描 | 定位是**测绘**不是**打点**。一个内网测绘工具带上 8000 条 PoC，在政务网里等于把"合规的资产盘点"变成"未经授权的渗透测试"，授权边界立刻模糊 |
| 文件泄露检测（.git / .svn / 备份包） | 同上：这是**取用**行为，不是**观察**行为。真要做，也该是单独授权、单独开关的模块 |
| GitHub / 代码仓库关键字监控 | 面对的是"代码外泄"，属于外部情报面，与内网被动测绘不是同一件事；且会把数据送出内网 |
| ICP 备案 / 天眼查联动 | 依赖公网查询接口，与"零外网依赖、离线可部署"的交付前提冲突 |

一句话：**StarMap 只做"看见"，不做"拿走"和"验证"。** 这条线划在哪儿，是从部署场景倒推的，
不是从功能清单倒推的。

### 还没做（确实缺，按价值排序）

| 缺口 | 价值 | 为什么这版没做 |
|---|---|---|
| **告警通道**（钉钉/飞书/企微/邮件/Webhook） | 高 | 现在所有结论都要人主动打开页面才看得到。内网工具最常见的死法是"部署了没人看" |
| **站点截图** | 中 | 需要 headless 浏览器，与"单二进制、零外部依赖"冲突，要么引入 100MB+ 的依赖，要么退化成"抓 HTML 存一份" |
| **JS 里提取域名 / AK-SK** | 中 | 需要下载并解析 JS，是主动取用行为，与上面"只看见不拿走"的边界冲突，需要单独评估授权 |
| **资产变更视图覆盖主机** | 中 | 1.6 的变更视图只覆盖端口与站点。主机级"新上线/下线"目前要从台账对照里间接看 |

### 结论

- **如果你的目标是"内网里有什么、哪个是账外的、证书哪个要到期了"** —— 达到了，
  而且比 ARL 多一层被动测绘与账实对照。
- **如果你的目标是"扫完顺手验证漏洞"** —— 没达到，且按当前定位不会做。
  需要的话应该另起一个明确授权的模块，而不是塞进测绘工具里。
- **如果目标是"出事能第一时间知道"** —— **还差告警通道**，这是 1.8 的第一优先级。

---

## 七、升级注意事项

1. **首次启动会跑时间列迁移**，13 张表 22 个列。10 万行级别的库在机械盘上大约几秒，
   期间服务正常启动、只是这批数据的时间列在转换。转换行数记在 `meta` 表
   （`SELECT value FROM meta WHERE key='schema.time_utc'`）。
2. **迁移不可逆**（时区信息被抹成 UTC）。升级前请先备份 `starmap.db`——
   虽然转换保证"时刻不变"，但**回退到 1.6.x 之后，旧版本的本地时区假设会读到 UTC 文本**。
3. **`/api/report` 与 `/api/export/sites.csv` 需要 operator 及以上角色**。
4. **站点视图依赖新列**。升级后老数据里 `http_status` / `cert_issuer` 为空，
   站点数会偏少（只有标题或 Server 的老端口仍能识别为站点）。**重扫一次即可补全**：
   `POST /api/discover/run`。不重扫不会报错，只是站点页看起来比预期少。
5. 配置文件无新增必填项。

---

## 八、已知短板（未解决，不粉饰）

- **SQLite 单写者**：写入仍是全局串行。当前压测 5378 RPS 足够，但这是天花板，不是起点。
- **WAL 长到几十 MB 不收缩**：长时间高频写入后需要手工 `VACUUM`，尚未做自动 checkpoint 调优。
- **任务进度不落库**：运行中的进度只在内存，进程重启后任务账里那一条会停在"running"。
- **变更视图只覆盖端口与站点**，不含主机级新增/下线。
- **导出未异步化**：20 万行上限内是流式写、不占内存，但请求会一直挂着。
- **站点报表清单限 50 条**：超过的只能去页面看，不进入报表。
- **无告警通道**：所有结论都要人主动打开页面。这是 1.8 的第一优先级。

---

## 九、文件清单

新增：

| 文件 | 内容 |
|---|---|
| `internal/store/timeutc.go` | 写入口 UTC 归一化 + 存量迁移 + `dbx`/`txx`/`stmtx` |
| `internal/store/timeutc_test.go` | 包装层每个方法的直接用例 + 迁移参数快路径 |
| `internal/store/sites.go` | 站点派生视图、统计、变更、标注、孤儿清理 |
| `internal/store/sites_test.go` | 派生判据（含 3389 只有证书不算站点）、去重、标注、统计 |
| `internal/store/sites_capacity_test.go` | 2 万 / 5 万站点容量回归 + benchmark |
| `internal/api/sites.go` | 7 个接口 + CSV 导出 |
| `internal/api/sites_test.go` | 接口、标注校验、CSV 防注入、报表 XSS |
| `internal/api/report.go` | 单文件 HTML 报表（`html/template`） |
| `web/sites.html` | 站点资产页（统计卡 / 筛选 / 详情抽屉 / 标注表单） |
| `test/seedports/main.go` | 往库里灌端口/站点数据的压测喂数器（含证书边界） |
| `docs/architecture.svg` | 分层架构图 |

修改：

| 文件 | 改动 |
|---|---|
| `internal/store/sqlite.go` | `db` 改为 `*dbx`、`meta`/`site_meta` 表、ports 加 6 列、`portUpsertArgs` 抽取、`stalePortStats` 逐批回调 |
| `internal/model/model.go` | `PortRecord` 加 6 字段；新增 `Site` / `SiteStats` / `SiteMeta` |
| `internal/api/server.go` | 站点与报表路由 |
| `internal/discover/runner.go` | 指纹结果写入 6 个新字段 |
| `internal/store/timefmt_test.go` | 时区用例翻转 + 迁移用例 + 三写路径回归 |
| `internal/store/changes_capacity_test.go` | 耗时断言改为执行计划守卫 |
| `internal/api/rbac_test.go` | 站点路由 6 条断言 |
| `web/assets/api.js` `web/assets/app.js` | 客户端方法 + 导航项 + `globe` 图标 |
| `internal/version/version.go` | 1.6.1 → 1.7.0 |

---

## 十、怎么自己复现这一版的数字

```bash
# 门禁
make lint                # gofmt + vet + staticcheck
go test ./... -count=1
go test ./... -count=1 -coverprofile=coverage.out && go tool cover -func=coverage.out | tail -1

# 站点容量（2 万行端口 / 1 万站点，含首页、计数、统计三段耗时）
go test ./internal/store -run 'TestListSitesScales' -count=1 -v

# 变更视图执行计划守卫
go test ./internal/store -run 'TestPortChanges' -count=1 -v

# 时间列迁移
go test ./internal/store -run 'TestNormalizeTimeColumns|TestAllWritePathsStoreUTC' -count=1 -v

# 站点页在真实规模下的手感（先灌数据，再起真实进程打开页面）
go run ./test/seedports -db /tmp/sm.db -hosts 4000 -per-host 12
./starmap -config configs/config.yaml   # db_path 指向 /tmp/sm.db
```
