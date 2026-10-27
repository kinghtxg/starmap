# StarMap 部署与运维手册

> 适用版本：1.4.0 · 更新于 2026-10-27
> 配套：[架构与实现](ARCHITECTURE.md) · [安全模型](SECURITY.md) · [探针部署](PROBE.md)

---

## 1. 部署前检查

| 项 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Linux x86_64 / arm64，macOS，Windows | 跨平台构建，CI 覆盖四平台 |
| 内存 | ≥ 2GB | 1 万节点规模实测常驻约 300–500MB |
| 磁盘 | ≥ 10GB，SSD 优先 | SQLite 单文件，端口记录增长最快 |
| 网络 | 能收到镜像流量，或部署探针 | 被动为主；无流量时系统是空的（不是坏了）。探针见 [PROBE.md](PROBE.md) |
| 权限 | 普通用户即可 | 实时抓包才需要 `CAP_NET_RAW` / root |
| 端口 | 默认 `127.0.0.1:8080` | **默认只监听回环**，对外请走反代 |

> 为什么默认只监听回环：这是一个"内网全量资产清单"系统，裸奔在 0.0.0.0 上
> 等于把资产底账公开。要对外提供服务，请显式改 `listen_addr` 或加反代。

---

## 2. 五分钟部署

### 2.1 直接用二进制

```bash
# 从 Release 下载对应平台包，或自己构建：
git clone https://github.com/kinghtxg/starmap.git && cd starmap
make build            # 产物在 dist/starmap
# 或：go build -o starmap ./cmd/starmap

mkdir -p /opt/starmap/data
cp starmap /opt/starmap/
cd /opt/starmap
./starmap -config config.yaml     # 首次启动会自动建库
```

最小配置 `config.yaml`：

```yaml
listen_addr: "127.0.0.1:8080"
db_path: "/opt/starmap/data/starmap.db"
log_level: "info"
log_format: "json"          # 生产建议 json，便于日志平台采集
```

访问 `http://127.0.0.1:8080` → 默认无认证（`auth.mode: none`），身份为 admin。

### 2.2 用 systemd 托管

```ini
# /etc/systemd/system/starmap.service
[Unit]
Description=StarMap
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=starmap
WorkingDirectory=/opt/starmap
ExecStart=/opt/starmap/starmap -config /opt/starmap/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
# 只读系统加固（实时抓包需要放开 CAP_NET_RAW）
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/starmap/data

[Install]
WantedBy=multi-user.target
```

```bash
useradd -r -s /sbin/nologin starmap
chown -R starmap: /opt/starmap
systemctl enable --now starmap
journalctl -u starmap -f
```

### 2.3 反向代理（nginx）

**关键：必须配 `trusted_proxies`**，否则审计里的操作人全是 `127.0.0.1`。

```nginx
server {
    listen 80;
    server_name starmap.internal;

    client_max_body_size 200m;      # PCAP 上传上限

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;    # 大拓扑序列化 / 长扫描
        proxy_send_timeout 300s;
    }
}
```

```yaml
# config.yaml 里对应加：
trusted_proxies:
  - 127.0.0.1/32          # nginx 与本机同机
  # - 10.0.0.0/8          # nginx 在其它机器时填它的网段
```

不配的后果（实测）：所有请求来源都是反代地址，
① 审计日志的操作人全变成反代 IP；② 登录失败限流的"IP 维度"会把全网用户当成一个人。
代码里对回环地址做了特殊处理（跳过 IP 维度），所以不会全员锁死，但审计依然失真。

### 2.4 启用认证（可选）

```yaml
auth:
  mode: local            # none | local | oidc
  users:
    - username: admin
      display_name: 系统管理员
      role: admin
      # 推荐用 bcrypt 而不是明文（明文会在日志里告警）
      password_bcrypt: "$2a$10$..."
    - username: auditor
      display_name: 审计员
      role: viewer
  session_secret: "至少32字节的随机串"   # 不配则每次重启失效所有会话
  cookie_secure: false   # 内网 http 保持 false；走 https 时改 true
```

生成 bcrypt：`./starmap -hash-password '你的密码'`（若版本没有该子命令，用 `htpasswd -bnBC 10 "" '密码' | tr -d ':\n'`）。

**三级角色**：

| 角色 | 能做什么 |
|---|---|
| `viewer` | 只读：拓扑、事件、资产、端口、台账、审计、配置读取 |
| `operator` | + 复核事件、维护白名单/域名、导入 PCAP、触发探测、启停抓包、归档资产、发起扫描 |
| `admin` | + 改配置、删数据（白名单/域名/资产/台账/探针） |

OIDC（APSSO）接入见 [AUTH-APSSO.md](AUTH-APSSO.md)。

---

## 3. 配置项全表

`config.yaml` 与界面「系统配置」是同一份配置：界面上改的会落盘，
重启后仍在（启动时 `mergeRuntimeConfig` 会把持久化值合并回来）。

### 3.1 探测与采集

| 键 | 默认 | 说明 |
|---|---|---|
| `probe_enabled` | `false` | 主动探测（ARP/ICMP/Traceroute）总开关 |
| `capture_enabled` | `false` | 实时抓包总开关（需 `-tags pcap` 构建） |
| `capture_interfaces` | `[]` | 抓包网卡，每行一个；空=启动时报错而非静默无数据 |
| `capture_bpf` | `""` | BPF 过滤表达式，如 `tcp port 443` |
| `probe_token` | `""` | 探针上报令牌；空=不校验。**对外开放时必须配** |

### 3.2 拓扑引擎

| 键 | 默认 | 说明 |
|---|---|---|
| `aging_seconds` | `86400` | 边老化：超过该时长无流量的边移除 |
| `aggregate_threshold` | `20` | 单个 /24 成员数达到该值才折叠成聚合节点 |
| `noise_bytes` | `400` | 降噪：会话字节数低于此值**且**满足下方两条才丢弃 |
| `noise_packets` | `4` | 降噪：包数低于此值 |
| `noise_duration_sec` | `2` | 降噪：持续时长低于此值（秒） |
| `reverse_proxy_hosts` | `10` | 单 IP 对外承载多少个 Host 判为反向代理 |
| `long_conn_seconds` | `3600` | 长连接阈值（frp 判定用） |
| `heartbeat_max_bytes` | `64` | 心跳包体积阈值 |

### 3.3 检测规则

规则阈值多数写死在 `internal/detect/*.go` 里（避免配置项爆炸），
可调的只有上面 `reverse_proxy_hosts` / `long_conn_seconds` / `heartbeat_max_bytes`。
事件去重窗口固定 24 小时（`DedupWindow`）。

### 3.4 资产与扫描

| 键 | 默认 | 说明 |
|---|---|---|
| `unarchived_offline_hours` | `72` | 未归档主机离线超该时长自动清理；0=不清理 |
| `archive_offline_seconds` | `600` | 归档主机 last_seen 超该值判离线 |
| `nmap_path` | `""` | nmap 路径；空=按 `nmap` 探测 |
| `scan_ports` | `1-65535` | nmap 端口范围 |
| `scan_rate` | `T4` | nmap 速率模板 T0–T5 |
| `discover_enabled` | `false` | **主动发现总开关**（内置扫描，与 `probe_enabled` 是两种授权风险） |
| `discover_profile` | `quick` | `quick`(108) / `standard`(1149) / `full`(65535) |
| `discover_rate_pps` | `800` | 全局每秒连接上限。**政务网老交换机建议 ≤800** |
| `discover_concurrency` | `256` | 单主机并发连接（上限 2048） |
| `discover_timeout_ms` | `800` | 单端口超时（800–10000） |
| `discover_fingerprint` | `true` | 是否做服务指纹 |
| `discover_max_fingerprints` | `32` | 单主机最多对几个端口做指纹（上限 256） |
| `discover_window` | `""` | 扫描时间窗口，如 `22:00-06:00`（支持跨夜）；空=全天 |
| `discover_sec` | `0` | 周期扫描间隔（秒）；**0 = 仅手动触发** |
| `discover_cidrs` | `[]` | 周期扫描网段；仅当 `discover_sec > 0` 时生效 |

### 3.5 自动发现（ping 层）

| 键 | 默认 | 说明 |
|---|---|---|
| `auto_discovery_enabled` | `false` | 周期探活总开关 |
| `auto_discovery_sec` | `1800` | 每轮间隔 |
| `auto_discovery_cidrs` | `[]` | 扫描网段 |
| `auto_discovery_method` | `arp` | `arp` / `icmp` |
| `auto_discovery_follow_discovered` | `false` | 自动纳入流量里新发现的网段 |
| `auto_discovery_exclude_cidrs` | `["169.254.0.0/16"]` | 排除网段（防误扫） |
| `auto_discovery_max_cidrs` | `64` | 单轮网段上限 |

### 3.6 服务与安全

| 键 | 默认 | 说明 |
|---|---|---|
| `listen_addr` | `127.0.0.1:8080` | 监听地址 |
| `db_path` | `starmap.db` | SQLite 路径 |
| `audit_retention_days` | `90` | 审计保留天数；0=不清理 |
| `event_retention_days` | `180` | 事件保留天数（只清已处置的）；0=不清理 |
| `cors_origins` | `[]` | CORS 白名单；空=仅同源 |
| `trusted_proxies` | `[]` | 可信反代网段；空=不解析 XFF |
| `session_max_count` | `200000` | 会话表上限 |
| `session_idle_seconds` | `300` | 会话静默回收阈值 |
| `session_max_age_seconds` | `21600` | 单会话最长存活 |
| `log_level` | `info` | `debug`/`info`/`warn`/`error`，可热改 |
| `log_format` | `text` | `text`/`json`，**改后需重启** |
| `metrics_enabled` | `true` | 是否暴露 `/metrics`，**改后需重启** |
| `metrics_token` | `""` | Prometheus 抓取令牌；空=仅 admin 会话/回环可访问 |

> **哪些能热改**：界面上所有输入框都能立即生效并落盘，例外已在字段说明里标注
> （`listen_addr` / `log_format` / `metrics_enabled` 需重启）。系统不假装热改这些值——
> 界面回显仍是旧值，避免"看着改了其实没变"。

---

## 4. 升级

```bash
# 1. 备份（SQLite 单文件，直接拷即可，WAL 模式下建议先 checkpoint）
sqlite3 data/starmap.db "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
cp -a data/starmap.db data/starmap.db.bak.$(date +%F)

# 2. 替换二进制并重启
systemctl stop starmap
cp starmap.new /opt/starmap/starmap
systemctl start starmap

# 3. 验证
curl -s http://127.0.0.1:8080/api/health          # 版本号
journalctl -u starmap -n 50 --no-pager            # 看有无迁移告警
```

**数据库兼容性**：升级只做 `ALTER TABLE ADD COLUMN`，不重建表、不改类型。
老库直接启动即可，无需迁移脚本。降级不保证（新列会被旧版本忽略，但不会回退数据）。

**升级后必查三件事**：

1. `/api/health` 版本号对不对；
2. 拓扑能出来（节点数不为 0）；
3. 事件列表能打开（`events` 表新增了索引，首次查询会稍慢）。

---

## 5. 监控

### 5.1 健康检查

```bash
curl -s http://127.0.0.1:8080/api/health
# {"status":"ok","time":"2026-10-27T11:14:27Z","version":"1.2.0"}
```

### 5.2 Prometheus

```yaml
scrape_configs:
  - job_name: starmap
    static_configs:
      - targets: ["127.0.0.1:8080"]
    # 配了 metrics_token 时：
    # authorization:
    #   type: Bearer
    #   credentials: <token>
```

关键指标（前缀 `starmap_`）：节点数、边数、活跃会话、事件总数、丢弃会话数、
HTTP 请求直方图。告警建议：

| 告警 | 条件 | 含义 |
|---|---|---|
| 会话丢弃 | `rate(starmap_sessions_dropped_total[5m]) > 0` 持续 10 分钟 | 流量超过容量上限，需要调 `session_max_count` 或分流 |
| 节点数断崖 | 节点数 1 小时内下降 > 30% | 可能是老化参数被改、或探针集体离线 |
| 事件静默 | 24 小时无新事件 | 检测引擎停了，或规则被白名单全抑制 |

### 5.3 日志

```bash
journalctl -u starmap -f              # 跟随
journalctl -u starmap -p err          # 只看错误
grep '"level":"ERROR"' app.log | jq   # json 格式时
```

每条 HTTP 日志都有 `request_id`，前端报错时让对方提供该 id 可直接定位。

---

## 6. 排障手册

| 症状 | 可能原因 | 处理 |
|---|---|---|
| 页面能开但拓扑为空 | 没有流量 / 探针没上报 / 报文被降噪 | 看 `/api/stats` 的 `packets`；导入一份 PCAP 验证 |
| 资产页数字不变 | `syncAssets` 5 秒节流；或节点未建 | 等 5 秒刷新；看拓扑里有没有该设备 |
| 事件一直不产生 | 检测周期未跑 / 全被白名单抑制 / 学习期未过 | 看 `/api/audit` 有无 `event_*`；检查白名单 |
| 登录报 429 | 失败次数触发限流（5 次/5 分钟，或 20 次/15 分钟按 IP） | 等锁定期结束；确认没配错密码 |
| 审计里操作人全是 127.0.0.1 | 反代未配 `trusted_proxies` | 见 2.3 |
| 实时抓包按钮灰 | 未用 `-tags pcap` 构建，或缺 libpcap/权限 | 页面会显示具体原因；改用 PCAP 导入 |
| `/metrics` 403 | 未配 `metrics_token` 且非 admin 会话 | 配 token 或用 admin 登录后访问 |
| 端口记录翻不到更多页 | 单页上限 5000 条（`?limit=` 会被夹取） | 正常行为；用关键字搜索收窄，或翻页（`?offset=`） |
| 深度发现 503 | `discover_enabled=false` | 系统配置里开启（先确认已获授权） |
| 升级后拓扑少了很多节点 | 老库 `node_key` 回填中 / 老化参数变化 | 看日志有无 `restore` 相关告警 |
| 磁盘持续增长 | 端口记录 / 会话表 | 调小保留期；`ports` 按网段清理 |

**常用排查命令**：

```bash
# 库里各表行数
sqlite3 data/starmap.db "SELECT 'nodes',COUNT(*) FROM nodes UNION ALL SELECT 'edges',COUNT(*) FROM edges
  UNION ALL SELECT 'events',COUNT(*) FROM events UNION ALL SELECT 'assets',COUNT(*) FROM assets
  UNION ALL SELECT 'ports',COUNT(*) FROM ports UNION ALL SELECT 'audit',COUNT(*) FROM audit;"

# 最近 20 条审计
sqlite3 -header data/starmap.db "SELECT created_at,actor,action,target FROM audit ORDER BY id DESC LIMIT 20;"

# 事件按类型分布
sqlite3 -header data/starmap.db "SELECT type,status,COUNT(*) FROM events GROUP BY type,status;"
```

---

## 7. 备份与恢复

```bash
# 备份（停服务最稳；不停也可，WAL 模式下拷 .db + -wal + -shm 三个文件）
systemctl stop starmap
tar czf starmap-$(date +%F).tgz data/starmap.db config.yaml
systemctl start starmap

# 恢复
systemctl stop starmap
tar xzf starmap-2026-10-27.tgz
systemctl start starmap
```

备份策略建议：每日全量 + 保留 30 天。DB 大小主要取决于 `ports` 与 `sessions` 表，
1 万台设备、跑一个月的典型体积是几百 MB 到几 GB。
