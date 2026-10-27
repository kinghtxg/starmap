# StarMap 探针（starmap-probe）部署手册

> 一句话：在一台**能看见流量**的机器上跑一个单文件程序，它抓包 → 聚合成会话 →
> 上报给 StarMap 服务端。不需要装 Wireshark，不需要 gcc，不需要 libpcap。

---

## 1. 为什么要有探针

StarMap 有三种数据进法，各有各的适用场景，**探针是唯一能大规模铺开的那种**：

| 方式 | 怎么用 | 代价 | 什么时候用 |
|---|---|---|---|
| 服务端实时抓包 | 服务端进程直接开网卡 | 需要 `-tags pcap` + CGO + libpcap；只能装在"能看见流量"的那一台 | 服务端本来就架在镜像口 |
| PCAP 上传 | 上传 `.pcap` 文件 | 事后分析，不实时；文件可能很敏感 | 应急排查、取证、离线复算 |
| **探针上报** | 每台探针抓本地流量，只上报**会话元数据** | 一台机器一个文件，无依赖 | **业务网各处都要覆盖时** |

关键差别在最后一行：探针上报的是"谁在什么时候和谁通信、用了什么协议、
SNI/JA3/JA4 是什么、传了多少字节"，**不上报载荷**。所以它可以在业务网里
铺很多个，而不用把抓包文件搬来搬去。

---

## 2. 三种采集后端

探针不绑定 libpcap，自己实现了三个后端，按平台自动选：

| 后端 | 平台 | 依赖 | 权限 | 说明 |
|---|---|---|---|---|
| `afpacket` | Linux | **无** | root 或 `CAP_NET_RAW` + `CAP_NET_ADMIN` | 直接开 `AF_PACKET` 原始套接字，纯 Go syscall |
| `npcap` | Windows | 已装 **Npcap**（Wireshark 会带装） | 管理员 | 通过 `syscall` 调 `wpcap.dll`，**不需要 CGO / 不需要 Wireshark** |
| `exec:<命令>` | 全平台 | 已装 `tcpdump`/`dumpcap`/`tshark` | 视命令而定 | 命令往 stdout 吐 pcap 就能用 |
| `file:<路径>` | 全平台 | 无 | 无 | 回放 pcap/pcapng，用于验证部署是否通 |

`-source auto`（默认）的选择顺序：Linux → `afpacket`；Windows → `npcap`；
其他（macOS/BSD）→ `exec:tcpdump`。

> 为什么坚持不碰 CGO：目标机器上往往没有编译器，也装不了开发包。
> 如果一个探针必须"先装 MinGW 才能构建"，它在多数内网里就永远装不上。
> 现在 `go build ./cmd/starmap-probe` 直接出一个能跑的单文件（约 14MB）。

---

## 3. 五分钟上手

### Windows

```powershell
# 1) 装 Npcap（若已装 Wireshark 可跳过；勾选 "Install Npcap in WinPcap API-compatible Mode"）
#    https://npcap.com/#download

# 2) 看有哪些网卡，以及它们的 IP —— 靠 IP 找对网卡，别靠名字
starmap-probe.exe -list-ifs

# 3) 先用 dry-run 确认能抓到包（不上报，只统计）
starmap-probe.exe -source npcap -iface "\Device\NPF_{...}" -dry-run -report 5s -verbose
#   看到 frames 在涨就说明抓到了。frames 一直是 0 见 §8 排障。

# 4) 正式上报（管理员 PowerShell）
starmap-probe.exe -config probe.yaml
```

### Linux

```bash
# 1) 交叉编译（在开发机上）或直接在本机构建
GOOS=linux GOARCH=amd64 go build -o starmap-probe ./cmd/starmap-probe

# 2) 看网卡
./starmap-probe -list-ifs

# 3) 给权限（二选一）
sudo setcap cap_net_raw,cap_net_admin=eip ./starmap-probe   # 推荐：不用 root 常驻
# 或者直接 sudo 运行

# 4) dry-run 验证
./starmap-probe -source afpacket -iface eth0 -dry-run -report 5s -verbose

# 5) 正式运行
./starmap-probe -config probe.yaml
```

### 先验证一遍再上线（推荐）

不接真实网卡也能验证整条链路通不通——拿仓库里的样例 pcap 回放一遍：

```bash
./starmap-probe -source file:testdata/out/frp_tunnel.pcap -once \
  -server http://192.168.31.100:8080 -probe-id probe-test -location 测试
# 日志出现 "服务端连通" 和 "回放结束 ... sessions_sent=1" 就是通了
```

对照实验：同样的 pcap 直接上传到服务端 `/api/ingest/pcap`，两边的**事件条数
必须一致**。仓库里的 `scripts/e2e-probe.sh` 就是自动做这件事的。

---

## 4. 配置文件

命令行参数适合临时排查，**部署用配置文件**。写进 systemd 单元或 Windows 服务的
`binPath` 时，十几个 flag 拼一行既没法审阅也没法 diff，改一个值要重建服务。

```yaml
# probe.yaml
server: http://192.168.31.100:8080
token: ""                     # 服务端配了 probe_token 就必须填
probe_id: probe-core-sw       # 唯一标识；默认取主机名
name: 核心交换机镜像            # 人读名称
location: 机房A 核心镜像口       # 位置，拓扑按它归纳，务必写清楚

source: auto                  # auto | afpacket | npcap | exec:<命令> | file:<路径>
iface: ""                     # 留空则自动挑（Windows 按私网 IP 挑）

interval: 10s                 # 会话增量上报间隔
report: 60s                   # 运行统计输出间隔
batch: 500                    # 单次上报最大会话数
buffer: 20000                 # 离线缓冲上限（条），满了丢最旧的并计数

# 必须和服务端配置一致，否则"长连接心跳"的判定两边会对不上
long_conn_seconds: 3600
heartbeat_max_bytes: 64

once: false                   # 采集源结束就退出（回放用）
dry_run: false                # 只统计不上报
```

优先级：**内置默认值 < 配置文件 < 命令行显式指定的参数**。
所以 `probe.yaml` 可以长期放着不动，排障时 `-report 5s -verbose` 临时覆盖即可。

> 注意：只有**真的写在命令行上**的 flag 才覆盖配置文件。`-interval 10s` 这种
> "和默认值一样"的写法也算显式指定。这是刻意用 `flag.Visit` 实现的，
> 否则命令行默认值会把配置文件里的值全部盖掉（这类工具的经典坑）。

---

## 5. 参数表

| 参数 | 默认 | 说明 |
|---|---|---|
| `-config` | 空 | YAML 配置文件 |
| `-server` | `http://127.0.0.1:8080` | 服务端地址 |
| `-token` | 空 | 对应服务端 `probe_token` |
| `-probe-id` | 主机名 | 探针唯一标识 |
| `-name` | 空 | 探针名称 |
| `-location` | 空 | 探针位置（强烈建议填） |
| `-source` | `auto` | `auto`/`afpacket`/`npcap`/`file:`/`exec:` |
| `-iface` | 空 | 网卡名 |
| `-interval` | `10s` | 会话增量上报间隔 |
| `-report` | `60s` | 运行统计输出间隔 |
| `-batch` | `500` | 单次上报最大会话数 |
| `-buffer` | `20000` | 离线缓冲上限 |
| `-long-conn` | `3600` | 长连接判定秒数 |
| `-heartbeat-bytes` | `64` | 心跳包字节阈值 |
| `-once` | false | 源结束即退出 |
| `-dry-run` | false | 只统计不上报 |
| `-list-ifs` | — | 列出网卡（含 IP）后退出 |
| `-verbose` | false | debug 日志 |
| `-version` | — | 打印版本 |

---

## 6. 常驻部署

### systemd（Linux）

```ini
# /etc/systemd/system/starmap-probe.service
[Unit]
Description=StarMap Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/starmap/starmap-probe -config /etc/starmap/probe.yaml
# 用 setcap 授权后不要用 root 跑：
User=starmap
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=5s
# 日志走 journald，直接 journalctl -u starmap-probe -f
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/starmap/starmap-probe
sudo systemctl daemon-reload && sudo systemctl enable --now starmap-probe
journalctl -u starmap-probe -f
```

停服务时探针会**先把采集停掉、把最后的会话冲给服务端**再退出，不会留一段数据空白。

### Windows 服务

Windows 自带的 `sc` 能把普通 exe 注册成服务（程序自己不实现服务控制协议，
因此需要"服务包装"或计划任务更稳）。两个现实可用的做法：

```powershell
# 做法一：任务计划程序（最简单，支持开机启动、失败重启）
schtasks /create /tn "StarMapProbe" /sc onstart /ru SYSTEM /rl HIGHEST ^
  /tr "\"C:\starmap\starmap-probe.exe\" -config C:\starmap\probe.yaml"

# 做法二：NSSM 包装成真正的服务
nssm install StarMapProbe "C:\starmap\starmap-probe.exe" -config C:\starmap\probe.yaml
nssm set StarMapProbe Start SERVICE_AUTO_START
nssm start StarMapProbe
```

必须以**管理员/SYSTEM** 运行：Npcap 打开网卡需要管理员权限，普通用户
`pcap_open_live` 会直接失败。

### 容器

抓包需要宿主机的网卡和 `NET_RAW`，所以用 host 网络 + 加权限：

```bash
docker run -d --name starmap-probe --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /etc/starmap/probe.yaml:/probe.yaml:ro \
  starmap-probe:1.4.0 -config /probe.yaml -source afpacket -iface eth0
```

---

## 7. 必须和服务端对齐的几项

这几项对不上不会报错，只会**悄悄让检测失效**，所以单独列出来：

| 探针侧 | 服务端侧 | 对不上的后果 |
|---|---|---|
| `token` | `probe_token` | 服务端返回 401，探针日志有明确报错，数据一条进不来 |
| `location` | — | 拓扑里该探针的节点归到「未知位置」，按位置归纳失效 |
| `long_conn_seconds` | `long_conn_seconds` | 探针判定的"长连接"和服务端规则口径不一致，心跳类规则时灵时不灵 |
| `heartbeat_max_bytes` | `heartbeat_max_bytes` | 同上 |

服务端也提供 `POST /api/ingest/probe` 的裸 JSON 接口（见 README），
自己写采集脚本时字段名必须和 `internal/api/server.go` 的 `probeFlow` 一致。

---

## 8. 排障手册

先看一行命令：**`-report 5s -verbose`**。它每 5 秒打一行

```
msg=探针运行中 frames=10719 packets=10667 sessions_sent=213 active=177
```

四个数字分别对应链路的四段，卡在哪一段一眼就能看出来：

```
frames=0            → 没抓到包（网卡/权限/混杂，见下）
frames 涨 packets=0 → 抓到了但不是 IP/TCP/UDP（少见，多是链路类型不对）
packets 涨 sessions_sent=0 → 抓到了但没聚出会话（流量太少，或聚合间隔没到）
sessions_sent 涨但页面没数据 → 上报失败（看 WARN 日志里的 err）
```

| 现象 | 常见原因 | 动作 |
|---|---|---|
| `frames=0`（Windows） | 选错网卡 | `-list-ifs` 看 **IP**，选有业务网 IP 的那块 |
| `frames=0`（Windows） | 不是管理员 | 用管理员 PowerShell / SYSTEM 运行 |
| `frames=0`（Windows） | 未装 Npcap | 装 Npcap 并勾选 WinPcap API 兼容模式 |
| `frames=0`（Linux） | 没权限 | `setcap cap_net_raw,cap_net_admin=eip` 或 root |
| `frames=0`（Linux，镜像口） | 没进混杂模式 | 日志里会有 `混杂模式未启用` 的 WARN；补 `CAP_NET_ADMIN` |
| 抓到的只有本机流量 | 交换机没做镜像 | 探针只能看见流经它的流量；要看全网需在交换机上配 SPAN/mirror |
| `服务端返回 401` | token 不一致 | 对齐 `probe_token` |
| `连不上服务端` | 地址/端口/防火墙 | `curl http://<server>/api/health` 先确认通 |
| `上报队列已满，丢弃最旧会话` | 服务端长时间不可达 | 看服务端为什么不可达；必要时调大 `buffer` |
| `服务端返回 413` | 单批太大 | 调小 `batch` |
| `无法识别的流格式（魔数 ...）` | exec 命令的输出不是 pcap | 命令里必须有 `-w -`；stderr 里的原因会一起打出来 |
| `等了 15s 没收到任何数据` | exec 命令启动了但不输出 | 手动跑一遍那条命令看报错 |

> Linux 上真实网卡的"能否看见别人流量"取决于**网络位置**，不取决于探针：
> 接在接入交换机的一个普通口上，只能看见本机流量；要看全局必须接镜像口/分光器，
> 或者把探针装在被监控的那台机器上。这不是配置问题，是物理拓扑问题。

---

## 9. 资源与容量

本机实测（Windows，192.168.31.0/24，抓了 10719 帧 / 12 秒）：

| 指标 | 实测值 |
|---|---|
| 单文件体积 | 约 14MB（`-ldflags "-s -w"` 后约 10MB） |
| 内存占用 | 约 37MB（工作集，含 129 个活跃会话） |
| 抓包吞吐 | 上述场景 900+ pps 无丢包；接收缓冲 4MB |
| 上报体积 | 一条会话约 300~500 字节 JSON，10s 一批 |

容量估算：一个 500 人的办公网，探针按 10s 上报、每分钟 1~3 千条会话，
**上行带宽占用在几十 KB/s 量级**，对业务网可忽略。

服务端侧的会话表有硬上限（默认 20 万条），超了会淘汰最旧的并计入
`SessionTable.Evicted`，不会无界增长。

---

## 10. 安全边界（务必读）

- **只上报会话元数据**：五元组、字节数、SNI/HTTP Host/JA3/JA4、XFF。
  不落盘、不上报任何应用层载荷内容。
- **无法解开 TLS**：看到的是 SNI 和证书/指纹，不是正文。
- **探针本身没有账号体系**：它只是一个出站客户端。请
  - 给 /api/ingest/probe 配置 `probe_token`（否则任何能访问服务端的人都能灌数据）；
  - 用主机防火墙限制探针机器只能出站访问服务端端口；
  - 探针需要 root/管理员权限，**部署前请走内部审批**——持有抓包权限的进程
    在合规上属于高敏感组件。
- **混合模式会看到不属于本机的流量**：接镜像口时探针能看到同网段其他主机的会话。
  这既是它的价值，也是它必须先报批的原因。
