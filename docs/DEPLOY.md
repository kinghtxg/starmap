# StarMap 星图 · 部署手册

> 适用版本：**1.8.0**（对应 `03-可执行程序\` 与 `版本\v1.8.0\`）
> 目标读者：要在自己的机器 / 服务器 / NAS 上把它跑起来的人。
> 三步就够：**放探针 → 起服务端 → 看状态**。下面每一步都写了"怎么确认这一步成了"。

---

## 0. 先读这三条，能省掉一半排障

**① 采集靠探针，不靠服务端。** 发布的服务端二进制是 `CGO_ENABLED=0` 构建的，
不含 libpcap，所以 **`capture_enabled` 在发布版里不起作用**（`internal/ingest/capture.go`
是 `//go:build !pcap` 的空实现）。要抓包，用 `starmap-probe` 去抓、往服务端报。
自己带 libpcap 从源码构建并加 `-tags pcap` 也能开服务端抓包，但那是开发用法。

**② 探针放哪儿，决定你能看见什么。** 这是被动分析产品的物理上限，不是配置问题：

| 探针位置 | 看得见 | 看不见 |
| --- | --- | --- |
| 核心交换机镜像口 | 全网东西向流量、谁在给谁服务、扫段、隧道 | 出 WAN 之后的一切 |
| 出口防火墙**内侧** | 谁在上网、出口路由器是谁（首跳 MAC）、NAT 后的内网源 | 公网侧出口地址（203.x） |
| 出口防火墙**外侧** | 公网出口地址、外联对端 | 内网任何东西（全是 NAT 后的地址） |
| 终端 / 服务器本机 | 自己这一条链路的完整细节 | 别人 |

> 想同时看到"内网出口设备"和"公网出口地址"，**得两个采集点**。单点做不到，
> 1.8.0 也没有为"验证一个拿不到的证据"去造假数据。

**③ 默认不主动发包。** `auto_discovery_enabled` / `discover_enabled` 默认全关，
`capture_enabled` 默认关。隔离网 / 政务网里这是刻意的：装上去先只看，不动。

---

## 1. 五分钟跑起来

### 1.1 Windows（演示 / 单机试用）

```
解压或直接进 03-可执行程序\windows-amd64\
双击 starmap.exe
```

- 默认监听 `127.0.0.1:8080`（**只回环**，同网段别人访问不到，这是有意的）
- 数据库落在**当前工作目录**的 `starmap.db`
- 浏览器打开 <http://127.0.0.1:8080>
- 命令行窗口是日志，关掉窗口 = 停服务

想让它能被别人访问：

```cmd
starmap.exe -config cfg.yaml
```

```yaml
# cfg.yaml
listen_addr: "0.0.0.0:8080"
db_path: "D:/starmap/starmap.db"
```

> `listen_addr` 改成 `0.0.0.0` 就等于把一个**默认无鉴权**的控制台放到网上了。
> 内网也请配合第 6 节的 nginx 反代 + 认证，或者至少 `probe_token` + 防火墙限制源 IP。

### 1.2 Linux / NAS

```bash
cd /opt
tar xf 源码-starmap-1.8.0.zip         # 只需要里面的二进制时，直接从 03-可执行程序 拷
cd starmap
chmod +x starmap starmap-probe

cat > cfg.yaml <<'EOF'
listen_addr: "0.0.0.0:8080"
db_path: "/var/lib/starmap/starmap.db"
log_format: "json"
probe_token: "换成你自己的随机串"
EOF

mkdir -p /var/lib/starmap
./starmap -config cfg.yaml
```

**确认这一步成了**：

```bash
curl -s http://127.0.0.1:8080/api/health
# {"status":"ok", ...}
```

看不到这个 JSON，就是没起来——先看日志，别急着配探针。

---

## 2. 服务端配置

配置文件是 YAML，路径由 `-config` 指定（默认 `configs/config.yaml`）。
**文件不存在不会报错**，会按内置默认值跑——所以"改了配置没生效"的第一嫌疑
永远是路径写错、读的不是这份文件。

合并规则：**文件里没写的字段保留默认值**；写了零值（`false` / `0` / `""`）的按写了算
（`metrics_enabled` 等默认 true 的开关另有 key 探测，`false` 是真的能关掉的）。

### 2.1 必须关心的十项

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `listen_addr` | `127.0.0.1:8080` | 对外服务改 `0.0.0.0:8080`，配反代时建议保持回环 |
| `db_path` | `starmap.db` | SQLite 单文件。**放本地盘，别放网络盘**（SQLite 锁在网络盘上不可靠） |
| `probe_enabled` | `false` | 允许探针上报。用探针就必须开 |
| `probe_token` | 空 | 设了就必须在探针侧填一样的值，否则上报 401 |
| `log_format` | `text` | 生产建议 `json`，日志平台直采 |
| `log_level` | `info` | 排查采集问题时临时调 `debug` |
| `aggregate_threshold` | `20` | 一个 /24 超过多少台就折叠成网段节点。调小图更干净但会藏细节 |
| `aging_seconds` | `86400` | 边老化时长 |
| `trusted_proxies` | 空 | **放在 nginx 后面必须填反代地址**，否则审计日志里所有人的 IP 都是 `127.0.0.1`，登录限流也会把所有人当成一个来源 |
| `auth.mode` | `none` | `none` / `local` / `oidc`，见第 6 节 |

### 2.2 容量与保留（长期在线跑必看）

被动分析是持续输入，不设上限几小时就能吃光内存/磁盘：

| 字段 | 默认 | 作用 |
| --- | --- | --- |
| `session_max_count` | 200000 | 内存会话表硬上限，超限先回收过期，再超就丢新会话并计数 |
| `session_idle_seconds` | 300 | 静默 5 分钟回收 |
| `session_max_age_seconds` | 21600 | 单会话最长 6 小时，防不关闭的长连接撑爆 |
| `session_retention_days` | 30 | 会话历史表保留天数（30 天 ≈ 数百 MB，实测 3 天 60 万行 / 148MB） |
| `audit_retention_days` | 90 | 审计日志 |
| `event_retention_days` | 180 | 风险事件，**只清已处置的**——保留期到了但没人复核的告警不会被静默删除 |
| `intel_retention_days` | 90 | 本地情报，90 天前的结论不再代表风险 |

### 2.3 主动发现（默认全关，开之前请确认授权）

两套，授权风险不同，**分开配置是有意的**：

| 字段 | 默认 | 作用 | 风险 |
| --- | --- | --- | --- |
| `auto_discovery_enabled` | `false` | 周期 ARP/ICMP 探活，让拓扑自生长 | 低：ping 一下 |
| `auto_discovery_method` | `arp` | `arp` / `icmp` | |
| `auto_discovery_cidrs` | 空 | 目标网段 | |
| `auto_discovery_follow_discovered` | `false` | 自动跟随流量发现的新网段 | **会扩大扫描范围**，政务网慎开 |
| `discover_enabled` | `false` | 内置 TCP 端口扫描 + 服务指纹（不依赖 nmap） | 高：会在目标侧留下大量连接记录 |
| `discover_profile` | `quick` | `quick`(108 端口) / `standard`(1149) / `full`(65535) | |
| `discover_rate_pps` | 800 | 全局速率上限（令牌桶） | |
| `discover_window` | 空 | 允许扫描的时间窗口，如 `"22:00-06:00"` | |

> `discover_*` 默认档位取 `quick` 而不是 `full`：先让人看到"100 个端口 30 秒出结果"，
> 再自己决定要不要把内网扫一遍。

### 2.4 威胁情报（可选）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `ti_enabled` | `false` | 回源总开关。**回源是外发行为**，把目标 IP 交给外部系统必须是显式动作 |
| `ti_endpoint` | 空 | 支持 `{ip}` 占位，否则自动追加 `?ip=` |
| `ti_api_key` | 空 | 不回显明文 |
| `intel_push_token` | 空 | 自有情报平台推送鉴权 |

本地库永远可用（推进来就能查，不外发）；回源**只查公网地址，内网一律不外发**。

---

## 3. Linux 常驻（systemd）

```ini
# /etc/systemd/system/starmap.service
[Unit]
Description=StarMap 星图 内网拓扑引擎
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=starmap
Group=starmap
WorkingDirectory=/opt/starmap
ExecStart=/opt/starmap/starmap -config /etc/starmap/cfg.yaml
Restart=always
RestartSec=5s

# 数据库目录要可写；其余保持只读
ReadWritePaths=/var/lib/starmap
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /sbin/nologin starmap
sudo mkdir -p /var/lib/starmap /etc/starmap && sudo chown -R starmap:starmap /var/lib/starmap
sudo cp cfg.yaml /etc/starmap/cfg.yaml
sudo systemctl daemon-reload && sudo systemctl enable --now starmap
sudo systemctl status starmap --no-pager
```

**注意**：探针要抓包，**不能**在 `User=starmap` 下跑。探针单独跑，用 root 或给
`CAP_NET_RAW,CAP_NET_ADMIN`（见第 4 节）。

---

## 4. 探针部署

探针是独立二进制，一台机器一个，可以多台同时报同一个服务端（拓扑会按 `location` 分组）。

### 4.1 最小配置

```yaml
# probe.yaml
server: http://10.20.1.5:8080
token: ""                      # 服务端配了 probe_token 就必须填
location: 机房A 核心镜像口      # 会进拓扑归纳，写清楚"在看哪里"，别写"未知"
source: auto
iface: ""
interval: 10s
```

```bash
./starmap-probe -config probe.yaml
```

### 4.2 先验证采集，再谈上报

```bash
./starmap-probe -list-ifs                    # 列出候选网卡与各自的 IP
./starmap-probe -config probe.yaml -dry-run -report 5s
```

`-dry-run` 只统计不上报。看到"会话数"在涨、`bytes` 是合理量级，
再摘掉 `-dry-run` 正式上报。

### 4.3 各平台采集源

| 平台 | `source` | 前置条件 |
| --- | --- | --- |
| Linux | `afpacket` | root 或 `CAP_NET_RAW` + `CAP_NET_ADMIN` |
| Windows | `npcap` | 装 [Npcap](https://npcap.com/)，**管理员运行**；`iface` 可传 `\Device\NPF_{GUID}` |
| 通用回退 | `exec:tcpdump` | 有 tcpdump 即可 |
| 回放 | `file:<路径>` | 配合 `once: true`，跑完就退出 |

### 4.4 回放 pcap（最快看到效果的路径）

服务端页面上「数据接入」直接上传也行；命令行等价：

```bash
./starmap-probe -server http://127.0.0.1:8080 \
  -source file:../04-示例数据/攻击场景pcap/nat.pcap -once -report 5s
```

`04-示例数据\攻击场景pcap\` 里的五份包分别对应隧道 / 多网 / 反代 / NAT 等场景，
传上去图上会立刻长出对应结构。

### 4.5 探针落成系统服务（Linux）

```ini
# /etc/systemd/system/starmap-probe.service
[Unit]
Description=StarMap 探针
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/starmap/starmap-probe -config /etc/starmap/probe.yaml
Restart=always
RestartSec=5s
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

---

## 5. NAS / ARM 板卡

用的是 `linux-arm64\starmap`。群晖 / 威联通上大致：

1. 开 SSH，把二进制和配置传到共享目录（如 `/volume1/docker/starmap/`）
2. `chmod +x starmap starmap-probe`
3. 前台跑一次确认能起：`./starmap -config cfg.yaml`
4. 常驻有两种：用「任务计划」开机触发，或 docker 里 `--network host` 挂一个 debian 精简镜像跑

**唯一要小心的**：`db_path` 一定放 NAS 的**本地卷**，不要放 iSCSI / 网络映射盘。
SQLite 在网络盘上的文件锁不可靠，症状是"偶尔 database is locked"，很难查。

---

## 6. 对外发布：nginx 反代 + 认证

### 6.1 先决定要不要开认证

- `auth.mode: none`（默认）：**零配置可用，等于谁连上谁能看、能改**。只适合本机/隔离调试。
- `auth.mode: local`：内置账号，密码哈希存配置。
- `auth.mode: oidc`：外接 APSSO / 标准 OIDC，**推荐**。安全产品不该再造一套密码库
  （合规红线，见 `AUTH-APSSO.md`）。

```yaml
auth:
  mode: "local"
  session_secret: "换成一串长随机值"     # 不填会每次重启踢掉所有会话
  session_ttl_seconds: 43200
  cookie_secure: false                  # 内网 http 保持 false；上了 https 改 true
  local_users:
    - username: "admin"
      password_hash: "<bcrypt 哈希>"
```

### 6.2 nginx

```nginx
server {
    listen 80;
    server_name starmap.corp;

    # 上传 pcap 会被这里卡住，默认 1m 太小
    client_max_body_size 512m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;      # 大 pcap 解析 + 扫描任务会跑很久
    }
}
```

**同时必须在服务端配**：

```yaml
trusted_proxies: ["127.0.0.1/32"]
```

不配这一行，审计日志里每个人的操作人都是 `127.0.0.1`，登录失败限流也会把
所有用户当成同一个来源——**反代本身没问题，是服务端不知道要信任谁**。

---

## 7. 部署后验收清单

按顺序打勾，任何一项不过都别往下走：

```bash
# 1. 服务活着
curl -s http://127.0.0.1:8080/api/health

# 2. 版本对得上
./starmap -version          # StarMap 星图 1.8.0+2757217

# 3. 探针报上来了（需要 probe_enabled: true）
curl -s http://127.0.0.1:8080/api/probes

# 4. 有数据进来
curl -s http://127.0.0.1:8080/api/stats

# 5. 拓扑不是空的
curl -s http://127.0.0.1:8080/api/topology | head -c 300
```

页面上再看三件事：

1. **拓扑页**右上角是否出现了「网关 / 路由器」这类设备（独立站在核心层，不在网段节点里）
2. **资产页**的「归属单位 / 归属人」——导入台账后会从台账回填，并打「台账」小标
3. **配置页**改一项 → 保存 → 刷新 → 值还在（证明真的落库）

---

## 8. 排障：按症状查

| 症状 | 最可能的原因 | 怎么办 |
| --- | --- | --- |
| 页面打不开 | `listen_addr` 还是 `127.0.0.1`，或防火墙 | 改 `0.0.0.0` + 放行端口；`ss -lntp \| grep 8080` |
| 能开页面，图一直是空的 | 没数据进来 | `curl /api/probes` 看探针在不在；探针加 `-report 5s` 看会话数涨不涨 |
| 探针上报 401 | `probe_token` 两边不一致 | 服务端与探针配置对齐（服务端留空 = 不校验） |
| 探针起不来 / 抓不到包 | 权限 | Linux 加 `CAP_NET_RAW`；Windows 用管理员 + 装 Npcap |
| 探针在跑，但会话数一直是 0 | 网卡选错 | `-list-ifs` 看候选和 IP，显式指定 `iface` |
| 流量数字大得离谱 | 老版本（1.5.1 之前的累加 bug） | 确认 `-version`；**1.5.1 之前写进库的字节数不可信且无法回算** |
| 图里"一堆主机直连公网"，找不到出口 | 网关被 /24 聚合折叠了（**1.8.0 前**的老缺陷） | 升级到 1.8.0；如仍出现，把 `aggregate_threshold` 调大观察 |
| 重启后网关不见了 | 同上，1.8.0 前 `gatewayMAC` 是内存态 | 升级到 1.8.0（已落成 `gateway` 标签随节点持久化） |
| 审计日志里操作人全是 `127.0.0.1` | 放在反代后面但没配 `trusted_proxies` | 填反代地址网段 |
| `database is locked` | 库放在网络盘 / 多个实例共用一个库 | 换本地盘，确认只跑一个实例 |
| 趋势图"今天"没数据 | 1.8.0 前按 UTC 建桶（时区缺陷） | 升级到 1.8.0 |
| 内存一直涨 | 会话表上限被调得太大 | 看 `session_max_count`；`/metrics` 里有会话数与丢弃计数 |

日志在 stdout。生产下 `log_format: json` + systemd 的 journald 或文件重定向：

```bash
journalctl -u starmap -f
# 或
./starmap -config cfg.yaml >> /var/log/starmap.log 2>&1
```

---

## 9. 升级与降级

**升级**（1.8.0 无 schema 变更，可直接覆盖二进制）：

```bash
sudo systemctl stop starmap
cp starmap /opt/starmap/starmap.new && chmod +x /opt/starmap/starmap.new
mv /opt/starmap/starmap.new /opt/starmap/starmap     # 同目录 mv 是原子的
sudo systemctl start starmap
curl -s http://127.0.0.1:8080/api/health && ./starmap -version
```

**探针要一起换**。服务端和探针版本不一致时 `/api/probes` 会显示成两代，
排查时容易误判。

**备份**：只有一个文件要紧。

```bash
sqlite3 /var/lib/starmap/starmap.db ".backup '/backup/starmap-$(date +%F).db'"
```

别直接 `cp` 正在写的 `.db`（有 WAL）。真要拷，连 `-wal`、`-shm` 一起拷，或者停服务再拷。

**降级**：二进制可以从 `版本\vX.Y.Z\` 里拿旧版。但**库不回退**——新版写进去的数据
旧版可能读不懂。有 schema 变更的版本（不是 1.8.0）降级前必须先恢复对应备份。

---

## 10. 已知边界（别当 bug）

- **不自建账号体系**：默认 `auth.mode=none`，需要管控时外接 APSSO/OIDC。
- **不做主动扫描取证**：主动发现默认可关，且只做 TCP connect + 指纹，不做漏洞利用。
- **端口明细是内存态**：重启后随新流量重建（不落库，和 TTL、软件指纹同类）。
- **内网 /24 聚合节点不合并成员端口**：聚合节点上的端口只属于它自己。
- **无集群 / 无多实例共享库**：单机 SQLite，定位就是一台机器上的运维工具。
- **`gateway` 标签单调**：设备不再转发也会一直带着（误判成出口比漏判安全）。
- **公网侧出口地址在局域网探针上不可见**：部署位置决定的，见第 0 节表。
- 前端有真实浏览器冒烟脚本，但没有像素级回归；视觉差异需人眼确认。
