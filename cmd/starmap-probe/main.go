// Command starmap-probe 独立探针：在一台机器上抓包，聚合会话后上报 StarMap。
//
// 全部依赖都不需要 CGO：
//
//	go build ./cmd/starmap-probe                             # 本机直接出单文件
//	GOOS=linux GOARCH=amd64 go build ./cmd/starmap-probe      # 交叉编译给 NAS / 服务器
//	GOOS=linux GOARCH=arm64 go build ./cmd/starmap-probe      # 树莓派 / ARM 盒子
//
// 四种采集来源：
//
//	-source afpacket -iface eth0                    Linux 原始套接字（需 root / CAP_NET_RAW）
//	-source npcap    -iface "\Device\NPF_{...}"     Windows（需已装 Npcap，管理员运行）
//	-source "exec:tcpdump -i eth0 -w - -U"          任何能往 stdout 吐 pcap 的命令
//	-source file:/path/to/cap.pcap                  回放（配合 -once）
//
// 部署用配置文件（推荐），排查用命令行参数（临时覆盖）：
//
//	starmap-probe -config probe.yaml
//	starmap-probe -config probe.yaml -report 5s -verbose   # 临时开详细统计
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"starmap/internal/agent"
	"starmap/internal/logging"
	"starmap/internal/version"
)

func main() {
	var (
		cfgPath   = flag.String("config", "", "配置文件路径（YAML）。命令行显式指定的参数优先级更高")
		server    = flag.String("server", "http://127.0.0.1:8080", "StarMap 服务端地址")
		token     = flag.String("token", "", "探针 token（对应服务端 probe_token）")
		probeID   = flag.String("probe-id", "", "探针标识（默认取主机名）")
		name      = flag.String("name", "", "探针名称（人读）")
		location  = flag.String("location", "", "探针位置，如「核心交换机镜像」「出口防火墙内侧」")
		source    = flag.String("source", "auto", "采集来源：auto | afpacket | npcap | file:<路径> | exec:<命令>")
		iface     = flag.String("iface", "", "网卡名（afpacket/npcap 用；npcap 传 \\Device\\NPF_{GUID}）")
		interval  = flag.Duration("interval", 10*time.Second, "会话聚合上报间隔")
		report    = flag.Duration("report", 60*time.Second, "运行统计输出间隔（排查采集是否正常时调到 5s）")
		batch     = flag.Int("batch", 500, "单次上报的最大会话数")
		buffer    = flag.Int("buffer", 20000, "离线缓冲上限（会话条数）")
		longConn  = flag.Int64("long-conn", 3600, "长连接判定秒数，需与服务端 long_conn_seconds 一致")
		heartbeat = flag.Int("heartbeat-bytes", 64, "心跳包字节阈值，需与服务端 heartbeat_max_bytes 一致")
		once      = flag.Bool("once", false, "采集源结束后立即退出（回放 pcap 用）")
		dryRun    = flag.Bool("dry-run", false, "不上报，只统计（验证采集是否正常）")
		listIfs   = flag.Bool("list-ifs", false, "列出可抓包的网卡后退出")
		verbose   = flag.Bool("verbose", false, "输出 debug 日志")
		showVer   = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("starmap-probe %s (%s/%s)\n", version.Full(), runtime.GOOS, runtime.GOARCH)
		return
	}
	if *listIfs {
		printIfaces()
		return
	}

	// 优先级：默认值 < 配置文件 < 命令行显式参数。
	// flag.Visit 只遍历"真的写了"的 flag，所以配置文件里的值不会被
	// 命令行参数的默认值悄悄盖掉——这是这类工具的经典坑。
	s := defaultSettings()
	if *cfgPath != "" {
		if err := loadSettings(*cfgPath, &s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			s.Server = *server
		case "token":
			s.Token = *token
		case "probe-id":
			s.ProbeID = *probeID
		case "name":
			s.Name = *name
		case "location":
			s.Location = *location
		case "source":
			s.Source = *source
		case "iface":
			s.Iface = *iface
		case "interval":
			s.Interval = interval.String()
		case "report":
			s.Report = report.String()
		case "batch":
			s.Batch = *batch
		case "buffer":
			s.Buffer = *buffer
		case "long-conn":
			s.LongConn = *longConn
		case "heartbeat-bytes":
			s.HeartbeatBytes = *heartbeat
		case "once":
			s.Once = *once
		case "dry-run":
			s.DryRun = *dryRun
		}
	})

	intervalD, reportD, err := s.durations()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	level := "info"
	if *verbose {
		level = "debug"
	}
	log := logging.Setup(logging.Options{Level: level, Format: logging.FormatText})

	id := s.ProbeID
	if id == "" {
		if h, err := os.Hostname(); err == nil {
			id = h
		} else {
			id = "starmap-probe"
		}
	}
	if s.Location == "" {
		log.Warn("未指定 location：拓扑里这台探针的归属会显示为「未知位置」，建议明确填写")
	}
	if s.Token == "" {
		log.Warn("未配置 token：服务端若启用了 probe_token，上报会被拒绝（401）")
	}

	src, err := openSource(s.Source, s.Iface, log)
	if err != nil {
		log.Error("采集源初始化失败", "err", err)
		os.Exit(1)
	}
	if !s.DryRun {
		checkServer(s.Server, log)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = agent.Run(ctx, agent.Config{
		Server:            s.Server,
		Token:             s.Token,
		ProbeID:           id,
		Name:              s.Name,
		Location:          s.Location,
		Interval:          intervalD,
		Report:            reportD,
		Batch:             s.Batch,
		Buffer:            s.Buffer,
		Once:              s.Once,
		LongConnSeconds:   s.LongConn,
		HeartbeatMaxBytes: s.HeartbeatBytes,
		DryRun:            s.DryRun,
		Logger:            log,
	}, src)
	if err != nil {
		log.Error("探针异常退出", "err", err)
		os.Exit(1)
	}
}

// checkServer 启动时探一次服务端。
//
// 为什么要有这一步：探针最常见的失败不是抓不到包，而是"抓到了、发不出去"——
// 地址写错、端口不通、服务端没起。如果不管，用户看到的现象是"探针在跑，
// 但页面上什么都没有"，然后去查抓包，查到怀疑人生。
// 这里提前打一行明确的日志（不退出：服务端可能稍后才起，探针会自己重试）。
func checkServer(server string, log *slog.Logger) {
	url := strings.TrimRight(server, "/") + "/api/health"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Error("服务端地址不合法", "server", server, "err", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warn("连不上服务端，会话会先攒在本地队列里并自动重试", "server", server, "err", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		log.Warn("服务端健康检查非 200", "server", server, "status", resp.StatusCode, "body", strings.TrimSpace(string(body)))
		return
	}
	var h struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &h)
	log.Info("服务端连通", "server", server, "server_version", h.Version)
}

// openSource 解析 -source 并构造采集后端。
func openSource(spec, iface string, log *slog.Logger) (agent.Source, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.HasPrefix(spec, "file:"):
		return agent.OpenFile(strings.TrimPrefix(spec, "file:"))
	case strings.HasPrefix(spec, "exec:"):
		return agent.OpenExec(strings.TrimPrefix(spec, "exec:"))
	case spec == "afpacket":
		return agent.OpenAFPacket(iface)
	case spec == "npcap":
		return agent.OpenNpcap(iface)
	case spec == "", spec == "auto":
		return openAuto(iface, log)
	default:
		return nil, fmt.Errorf("无法识别的 -source %q：可选 auto | afpacket | npcap | file:<路径> | exec:<命令>", spec)
	}
}

// openAuto 按平台挑默认后端。
// 判断顺序刻意如此：先看有没有原生能力，再看有没有现成命令，最后才报错。
func openAuto(iface string, log *slog.Logger) (agent.Source, error) {
	switch runtime.GOOS {
	case "linux":
		if iface == "" {
			iface = firstUpIface()
		}
		if iface == "" {
			return nil, fmt.Errorf("找不到可用网卡，请用 -iface 指定")
		}
		log.Info("自动选择采集后端", "source", "afpacket", "iface", iface)
		return agent.OpenAFPacket(iface)
	case "windows":
		if iface == "" {
			devs, err := agent.ListNpcapDevices()
			if err != nil {
				return nil, err
			}
			iface = pickDevice(devs)
			if iface == "" {
				return nil, fmt.Errorf("没有可抓包的网卡，请用 -list-ifs 查看")
			}
			log.Info("自动选择网卡", "iface", iface)
		}
		log.Info("自动选择采集后端", "source", "npcap", "iface", iface)
		return agent.OpenNpcap(iface)
	default:
		// macOS / BSD：系统自带 tcpdump，用它吐 pcap 比要求用户装 libpcap 现实得多。
		if iface == "" {
			iface = firstUpIface()
		}
		cmd := "tcpdump -i " + iface + " -w - -U -s 0 2>/dev/null"
		log.Info("自动选择采集后端", "source", "exec", "cmd", cmd)
		return agent.OpenExec(cmd)
	}
}

func firstUpIface() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(i.HardwareAddr) == 0 {
			continue // 只有真网卡才有 MAC
		}
		return i.Name
	}
	return ""
}

// pickDevice 从 Npcap 设备列表里挑一块"像真网卡"的。
// 列表里通常混着 WAN Miniport、Loopback、VMware/Hyper-V 虚拟网卡，
// 直接取第一个经常是错的——而且错得很安静：探针能起、日志正常，就是没数据。
//
// 判据顺序：① 有私网 IPv4（真正连在业务网上的网卡才有）→ ② 描述像物理网卡。
func pickDevice(devs []agent.Device) string {
	for _, d := range devs {
		for _, a := range d.Addrs {
			ip := net.ParseIP(a)
			if ip == nil || ip.To4() == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue // 127.x / 169.254.x 都是"没接上"的标志
			}
			if ip.IsPrivate() {
				return d.Name
			}
		}
	}
	good := []string{"ethernet", "以太网", "wi-fi", "wifi", "wlan", "wireless", "无线"}
	bad := []string{"loopback", "环回", "wan miniport", "npf_loopback"}
	for _, d := range devs {
		desc := strings.ToLower(d.Description)
		skip := false
		for _, b := range bad {
			if strings.Contains(desc, b) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, g := range good {
			if strings.Contains(desc, g) {
				return d.Name
			}
		}
	}
	if len(devs) > 0 {
		return devs[0].Name
	}
	return ""
}

func printIfaces() {
	fmt.Println("可抓包的网卡：")
	if runtime.GOOS == "windows" {
		devs, err := agent.ListNpcapDevices()
		if err != nil {
			fmt.Println("  枚举失败:", err)
			return
		}
		for i, d := range devs {
			ips := strings.Join(d.Addrs, ",")
			if ips == "" {
				ips = "（无 IP，多半没接网线或已停用）"
			}
			fmt.Printf("  [%d] %s\n      %s\n      IP: %s\n", i, d.Name, d.Description, ips)
		}
		fmt.Println("\n用法：-source npcap -iface \"\\Device\\NPF_{...}\"")
		return
	}
	ifs, err := net.Interfaces()
	if err != nil {
		fmt.Println("  枚举失败:", err)
		return
	}
	for _, i := range ifs {
		state := "down"
		if i.Flags&net.FlagUp != 0 {
			state = "up"
		}
		fmt.Printf("  %-16s %-18s %s  %s\n", i.Name, i.HardwareAddr, state, strings.Join(addrOf(&i), ","))
	}
}

// addrOf 返回网卡上的 IP 地址列表（不含链路层地址）。
func addrOf(ifc *net.Interface) []string {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.String())
		}
	}
	return out
}
