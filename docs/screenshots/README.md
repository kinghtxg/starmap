# 截图：来源与复现步骤

仓库里的 `docs/screenshots/*.png` 不是手绘稿，也不是 UI 稿，而是**在真实运行的服务上自动截图**得到的。
保留这份说明是为了让任何人（包括未来的自己）能在半小时内复现出同一批图，而不是"只有某台机器上拍得出来"。

## 1. 起一个干净的实例

```bash
# 任意临时目录，别放在仓库里（截图/库文件不进版本控制）
mkdir -p /tmp/starmap-shots && cd /tmp/starmap-shots

# 最小配置：只用回环地址 + 本地 SQLite
cat > cfg.yaml <<'YAML'
listen_addr: "127.0.0.1:18097"
db_path: "/tmp/starmap-shots/star.db"
probe_enabled: true
discover_enabled: true     # 「深度发现」要真扫一轮，必须打开
YAML

/go/bin/starmap -config cfg.yaml      # 或 dist/starmap-linux-amd64 -config cfg.yaml
```

## 2. 把数据灌到"看起来像真实网络"的量

空库拍出来的图全是空态，读者看不到能力。按下面顺序灌，缺一步就会少一类画面：

```bash
# ① 政务网五类典型场景（正常办公 / 一机两网 / 账外机 / 七层反代 / 代理上网）
go run testdata/simprobe.go -server http://127.0.0.1:18097 -rounds 3

# ② 五个合成 PCAP：隧道、代理、多网卡、办公网、反代
for f in testdata/out/*.pcap; do
  curl -s -F "file=@$f" http://127.0.0.1:18097/api/ingest/pcap > /dev/null
done

# ③ 端口记录（拓扑与端口页要有量，否则分页与统计都看不出效果）
#    注意它是直接写 SQLite 文件，不是打接口：给的是库路径，不是服务地址。
go run ./test/seedports -db /tmp/starmap-shots/star.db -hosts 120 -per-host 8

# ④ 一轮真实扫描：任务账、指纹、站点表都靠它产出
curl -s -X POST http://127.0.0.1:18097/api/discover/run \
  -H 'Content-Type: application/json' -d '{"targets":["127.0.0.1"],"profile":"quick"}'

# ⑤ 资产台账：不导入的话「台账对照」页只有空态
curl -s -X POST http://127.0.0.1:18097/api/ledger/import \
  -H 'Content-Type: application/json' \
  -d '{"batch":"2026 年第四季度台账","csv":"IP地址,MAC地址,主机名,归属单位\n10.10.1.10,02:00:0a:01:10:00,oa-pc-01,办公室"}'
```

台账要能同时体现四类差异（在册在网 / 台账外 / 台账僵尸 / IP 不符），否则那一页的"账实对照"讲不清楚：

- 正常条目 → IP 与 MAC 都对得上 → **在册在网**
- 只登记了网内不存在的 IP → **台账僵尸**
- 登记的 MAC 在网内某台机器上、但 IP 变了 → **IP 不符**
- 网内其余主机 → **台账外设备**

比例的讲究：台账要按"大部分对得上、少数差异"来造（例如 27 台主机里 21 条台账、16 台账实一致）。
全都不对得上会拍成一屏"网里全是影子设备"，读者会以为这在演示误报。

另外两类数据不进库也要补，否则拍出来是空的：

- **站点标注**：`POST /api/sites/meta` 给几个站点填名称 / 归属 / 标签，否则「标签」列整列是 `—`；
- **事件复核**：`POST /api/events/{id}/review` 处置掉两条（`confirm` 与 `false_positive` 各一条），
  否则状态列只有"待处置"一种。注意 `false_positive` 会**自动写白名单**，白名单页那张图要跟着重拍。

## 3. 拍

```bash
STARBASE=http://127.0.0.1:18097 \
STARDISCOVER=127.0.0.1 \
python3 scripts/shot.py
```

环境变量：

| 变量 | 作用 |
|---|---|
| `STARBASE` | 目标实例，默认 `http://127.0.0.1:18097` |
| `STARDISCOVER` | 给了目标才会拍 `discover.png`（会真扫一轮）；不给就跳过 |
| `STARLOGIN` | 开了认证的实例地址，用来拍 `login.png`；留空则跳过 |
| `SHOTOUT` | 输出目录，默认 `docs/screenshots`。想先看效果就指到临时目录 |
| `SHOTONLY` | 逗号分隔的文件名，只重拍这几张 |

> **一定要用 `SHOTONLY` 增量更新。** 拿一个数据很少的实例跑全量，会把已经拍得比较饱满的图覆盖成空表，
> 而 git 里看到的只是"图片变了"，很难察觉变差了。

有三张图不是"打开页面就拍"，因为默认视口下拍到的是页面**最没信息量**的那一屏：

| 图 | 额外动作 | 不这么做会怎样 |
|---|---|---|
| `ledger.png` | 切到「在册在网」筛选 | 默认「全部」按 账外→在册→IP不符→僵尸 排，首屏全是台账外，而它们的归属/位置必然为空——拍不出"台账补上了归属单位/负责人/位置" |
| `events.png` | 状态筛切换成「全部状态」 | 默认只筛待处置，图里永远是清一色"待处置"，看不出复核这条链路走过没有 |
| `site-detail.png` | 滚到 `#mTags` | 抽屉正文可滚动，停在顶部时标注表单被页脚切掉半行，只露出标签框的一条边 |

## 4. 校验（比截更重要的那一步）

截图只能证明"能渲染"，证明不了"排版是对的"。同一批页面跑一遍闸门：

```bash
STARBASE=http://127.0.0.1:18097 python3 scripts/visual-audit.py          # 1440x900
STARBASE=http://127.0.0.1:18097 python3 scripts/visual-audit.py --wide   # 2560x1440
```

它逐页实测：横向溢出、文字被裁、元素出界、控件小于 24px、控制台异常、4xx 响应；
对配置页额外断言"滚到底部时保存按钮仍在视口内"。退出码非 0 即有页面不达标。

判据为什么必须实测：肉眼看图会把"正常"看成"被裁"（缩放导致），也会把"被裁"看成"正常"（看不清）。

## 5. 文件清单

| 文件 | 页面 | 这张图要证明什么 |
|---|---|---|
| `topology.png` | 拓扑总览 | 泳道分组、风险锚点不参与聚合（红虚环）、图例与提示 |
| `topology-drill.png` | 拓扑下钻 | 下钻后网段内链路完整，其它网段补为上下文 |
| `topology-xff.png` | 节点详情 | XFF 还原出的客户端、通信对端列表 |
| `assets.png` | 主机资产 | 资产表、在线状态、归档入口 |
| `ports.png` | 端口记录 | 指纹列（产品 / 版本 / 证书 / favicon） |
| `ledger.png` | 台账对照 | 四类账实差异 + 筛选标签上的计数 |
| `events.png` | 风险事件 | 分页、级别徽章、处置入口 |
| `sites.png` | 站点资产 | 一级资产视图：标题 / 技术栈 / 证书剩余 / 特征标签 |
| `site-detail.png` | 站点详情抽屉 | 证书情报 + 人工标注表单（这一页唯一的写入口） |
| `changes.png` | 网络变更 | 趋势图 + 窗口内新增端口 |
| `tasks.png` | 发现任务 | 任务账：状态、进度、耗时、开始时间 |
| `task-detail.png` | 任务详情抽屉 | 每台主机扫出哪些端口 |
| `report.png` | 资产测绘报告 | 可单独保存 / 发邮件的自包含 HTML |
| `discover.png` | 深度发现弹窗 | 档位计划、扫描结果回执 |
| `domains.png` | 网络域 | 域卡片与 CIDR 列表 |
| `whitelist.png` | 白名单 | 多维度白名单 |
| `ingest.png` | 数据接入 | PCAP 导入 / 探针 / 抓包状态 |
| `logs.png` | 审计日志 | 操作留痕 |
| `settings.png` | 系统配置 | 分组配置项 + 底部的吸底保存条 |
| `login.png` | 登录（可选门卫） | 本地账号 / 外部身份源两种入口 |
