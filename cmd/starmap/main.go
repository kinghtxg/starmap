// StarMap 星图入口：装配 config → store → engine → detector → review → api，
// 抓包/PCAP导入/探针三路 PacketSource 汇入 Aggregator → Engine；优雅退出。
//
// 版本号见 internal/version（定版 1.0 起不再在代码里写死 V1.x）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"starmap/internal/api"
	"starmap/internal/config"
	"starmap/internal/detect"
	"starmap/internal/ingest"
	"starmap/internal/logging"
	"starmap/internal/metrics"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
	"starmap/internal/version"
)

// die 配置尚未读出来时（logger 还没建好）的致命错误出口。
// 不用 log.Fatalf：避免一个项目里同时存在两种日志格式。
func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}

// 默认预置网络域（ACCEPTANCE 8.1）
var defaultDomains = []model.NetDomain{
	{Name: "gov", CIDRs: []string{"10.0.0.0/8"}, Color: "#38BDF8"},
	{Name: "office", CIDRs: []string{"172.16.0.0/12"}, Color: "#4ADE80"},
	{Name: "internet", CIDRs: []string{"0.0.0.0/0"}, Color: "#94A3B8"},
	{Name: "prod", CIDRs: []string{"192.168.0.0/16"}, Color: "#FB923C"},
}

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "打印版本信息后退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("StarMap 星图 %s\n", version.Full())
		if version.BuildTime != "" {
			fmt.Printf("构建时间: %s\n", version.BuildTime)
		}
		return
	}

	// 1. 配置
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		die("加载配置失败", err)
	}
	// 1.1 结构化日志：必须在任何业务动作之前，否则早期日志是另一种格式
	logging.Setup(logging.Options{
		Level:  cfg.LogLevel,
		Format: logging.Format(cfg.LogFormat),
	})
	slog.Info("StarMap 启动",
		"version", version.Full(),
		"config", *cfgPath,
		"log_level", cfg.LogLevel,
		"log_format", cfg.LogFormat,
	)
	// 1.2 校验可选账号系统 / APSSO 配置（默认 none，永远合法）
	if err := cfg.Auth.Validate(); err != nil {
		slog.Error("认证配置非法", logging.Err(err))
		os.Exit(1)
	}

	// 2. 存储
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		slog.Error("初始化数据库失败", logging.Err(err), "db", cfg.DBPath)
		os.Exit(1)
	}
	defer st.Close()

	// 2.1 运行时配置覆盖（PUT /api/config 的持久化结果）
	if v, err := st.GetConfigKV("system_config"); err == nil && v != "" {
		var saved model.SystemConfig
		if json.Unmarshal([]byte(v), &saved) == nil {
			mergeRuntimeConfig(&cfg, &saved)
		}
	}

	// 2.2 预置网络域（空库时）
	if ds, err := st.ListDomains(); err == nil && len(ds) == 0 {
		for _, d := range defaultDomains {
			if _, err := st.CreateDomain(&d); err != nil {
				slog.Warn("预置网络域失败", "domain", d.Name, logging.Err(err))
			}
		}
	}

	// 3. 拓扑引擎 + 会话聚合器
	engine := topology.New(cfg)
	if ds, err := st.ListDomains(); err == nil {
		engine.SetDomains(ds)
	}
	// 3.1 恢复持久化拓扑（P0-2）：ListNodes/ListEdges 载入内存并按原 ID 重建索引，
	// 保证历史事件的 node_id 与白名单 node 维度在重启后仍指向同一个节点。
	if err := engine.AttachStore(st); err != nil {
		slog.Error("恢复持久化拓扑失败", logging.Err(err))
		os.Exit(1)
	}
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	// 会话表容量治理（V1.0）：被动抓包是持续输入，必须给会话表设上限与存活期。
	agg.SetLimits(cfg.SessionMaxCount, cfg.SessionIdleSeconds, cfg.SessionMaxAgeSeconds)

	// 4. 检测调度器 + 复核 + 探测器
	det := detect.New(st, engine, cfg)
	// 检测规则要的是「全表视图」（FRP 比对、多网融合、反代域名计数都要跨会话统计），
	// 因此这里必须接 Sessions（只读快照），不能接 Finalize（增量语义）。
	det.SessionsFunc = agg.Sessions
	rvw := review.New(st, engine)
	scanner := probe.New(engine)
	scanner.SetEnabled(cfg.ProbeEnabled)

	// 5. 报文总线：抓包 + 探针共用一个 channel
	packetCh := make(chan *parser.PacketInfo, 4096)
	// 探针上报通道消费泵
	go func() {
		for p := range packetCh {
			agg.Ingest(p)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 老化 goroutine
	engine.RunAging(ctx, time.Minute)
	// 拓扑批量落盘（P0-2）：2s 一次聚合写库，避免每个报文都写；ctx 取消时补一次 flush
	engine.RunPersist(ctx, 2*time.Second)
	// 审计日志保留期清理（§10.8，每日一次）
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if cfg.AuditRetentionDays > 0 {
					cutoff := time.Now().AddDate(0, 0, -cfg.AuditRetentionDays)
					if n, err := st.DeleteAuditLogsBefore(cutoff); err == nil && n > 0 {
						slog.Info("清理超期审计日志", "deleted", n, "retention_days", cfg.AuditRetentionDays)
					}
				}
			}
		}
	}()
	// 账外资产离线清理（V1.2）：未归档主机离线超阈值 → 自动从拓扑与资产库删除（10 分钟一次）
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cleanupOfflineAssets(st, engine, cfg)
			}
		}
	}()
	// 周期性：会话 → 拓扑 → 检测
	// 用一个 WaitGroup 保证退出时这条泵已经停下，避免退出落盘与它并发抽取同一批会话。
	var tickerWG sync.WaitGroup
	tickerWG.Add(1)
	go func() {
		defer tickerWG.Done()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, e := range agg.DrainNow().Entries {
					ses := e.Session
					engine.Ingest(&ses)
				}
			}
		}
	}()
	// 自动发现（V1.4）：周期性对目标网段做主动扫描，让拓扑"自生长"。
	// 默认关闭；需同时开启 probe_enabled（主动探测总开关）与 auto_discovery_enabled。
	// V1.5：auto_discovery_follow_discovered 开启后，自动跟随流量已发现的新网段，
	//       受排除列表与单轮上限约束，防止扫描面失控。
	if cfg.AutoDiscoveryEnabled && (len(cfg.AutoDiscoveryCIDRs) > 0 || cfg.AutoDiscoveryFollowDiscovered) {
		interval := time.Duration(cfg.AutoDiscoverySec) * time.Second
		if interval <= 0 {
			interval = 30 * time.Minute
		}
		method := cfg.AutoDiscoveryMethod
		if method == "" {
			method = "arp"
		}
		maxCIDRs := cfg.AutoDiscoveryMaxCIDRs
		if maxCIDRs <= 0 {
			maxCIDRs = 64
		}
		known := map[string]bool{} // 已纳入扫描的网段（用于识别"新网段"）
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			slog.Info("自动发现已启用",
				"interval", interval.String(), "method", method,
				"follow_discovered", cfg.AutoDiscoveryFollowDiscovered, "max_cidrs", maxCIDRs)
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					targets := buildScanTargets(cfg, engine, maxCIDRs, known)
					for _, cidr := range targets {
						res, err := scanner.Trigger(method, cidr)
						if err != nil {
							slog.Warn("自动发现扫描失败", "method", method, "cidr", cidr, logging.Err(err))
							continue
						}
						if res != nil && len(res.Hosts) > 0 {
							slog.Info("自动发现扫描完成",
								"method", method, "cidr", cidr, "hosts", len(res.Hosts))
						}
					}
				}
			}
		}()
	}
	go det.Run(ctx)

	// 启动时自动抓包（配置开启时）
	if cfg.CaptureEnabled && len(cfg.CaptureInterfaces) > 0 {
		if src, err := ingest.StartCapture(cfg.CaptureInterfaces, cfg.CaptureBPF); err != nil {
			slog.Error("抓包启动失败", "interfaces", cfg.CaptureInterfaces, logging.Err(err))
		} else {
			go func() {
				for p := range src {
					agg.Ingest(p)
				}
			}()
			slog.Info("抓包已启动", "interfaces", cfg.CaptureInterfaces, "bpf", cfg.CaptureBPF)
		}
	}

	// 6. API 服务
	// 6.1 指标集合：状态类全部用 GaugeFunc 现读现算，不依赖任何"记得推送"的埋点。
	//     两个 DB 统计走轻量查询（默认 15s 抓一次，代价可忽略）。
	var met *metrics.Metrics
	if cfg.MetricsEnabled {
		met = metrics.New(metrics.Providers{
			TopologyNodes: func() int {
				n, _ := engine.Counts()
				return n
			},
			TopologyEdges: func() int {
				_, e := engine.Counts()
				return e
			},
			SessionsActive: func() int { return agg.Stats().Active },
			SessionsDropped: func() int64 {
				return agg.Stats().Dropped
			},
			SessionsEvicted: func() int64 {
				return agg.Stats().Evicted
			},
			EventsPending: func() int {
				evs, err := st.ListEvents(model.EventStatusPending, "")
				if err != nil {
					return 0
				}
				return len(evs)
			},
			AssetsUnmanaged: func() int {
				as, err := st.ListAssets(model.AssetUnarchived)
				if err != nil {
					return 0
				}
				return len(as)
			},
		})
		slog.Info("指标导出已启用", "path", "/metrics",
			"auth", map[bool]string{true: "X-Metrics-Token", false: "admin 会话"}[cfg.MetricsToken != ""])
	}

	srv := api.NewRouter(api.Deps{
		Store:      st,
		Engine:     engine,
		Detector:   det,
		Reviewer:   rvw,
		Scanner:    scanner,
		Cfg:        &cfg,
		Aggregator: agg,
		PacketCh:   packetCh,
		PersistConfig: func(c model.SystemConfig) error {
			b, err := json.Marshal(c)
			if err != nil {
				return err
			}
			return st.SetConfigKV("system_config", string(b))
		},
		Version: version.String(),
		Metrics: met,
	})

	httpSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv,
		// V1.0 定版：补齐超时与头部上限。
		// 没有 ReadHeaderTimeout 的服务在内网也能被 Slowloris 拖死（占满连接不结束握手），
		// 这是所有"能上线"的 Go 服务的必填项。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,  // PCAP 上传走请求体，给足时间
		WriteTimeout:      120 * time.Second, // 拓扑大图序列化可能偏慢
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB，默认 1MB 但显式写死便于审计
	}
	go func() {
		slog.Info("StarMap 就绪",
			"version", version.Full(),
			"listen", cfg.ListenAddr,
			"db", cfg.DBPath,
			"capture", cfg.CaptureEnabled,
			"probe", cfg.ProbeEnabled,
			"metrics", cfg.MetricsEnabled,
		)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP 服务异常退出", logging.Err(err))
			os.Exit(1)
		}
	}()

	// 7. 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("收到退出信号，开始优雅退出", "signal", sig.String())
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	_ = httpSrv.Shutdown(shCtx)
	det.Stop()
	tickerWG.Wait() // 等会话泵退出，再补最后一轮落盘
	n := persistPendingSessions(agg, st)
	if err := engine.Flush(); err != nil {
		slog.Error("退出前拓扑落盘失败", logging.Err(err))
	}
	slog.Info("已退出", "flushed_sessions", n)
}

// persistPendingSessions 退出前把「还没落过库」的会话补写一遍，返回写入条数。
//
// 只写 First=true 的会话：会话在周期同步里已经被写过一次，退出时整表重插会产生重复行
// （历史实现就踩过这个坑 —— 每次优雅退出，sessions 表就翻一倍）。
func persistPendingSessions(agg *parser.Aggregator, st *store.Store) int {
	if agg == nil || st == nil {
		return 0
	}
	saved := 0
	for _, e := range agg.DrainNow().Entries {
		if !e.First {
			continue
		}
		ses := e.Session
		if _, err := st.SaveSession(&ses); err == nil {
			saved++
		}
	}
	return saved
}

// cleanupOfflineAssets 账外资产离线清理（V1.2）：
// 未归档主机 last_seen 超过 unarchived_offline_hours（默认 72h）→ 从拓扑与资产库删除。
// 归档主机仅动态标记离线（不删除），保留在资产台账。
func cleanupOfflineAssets(st *store.Store, eng *topology.Engine, cfg model.SystemConfig) {
	if cfg.UnarchivedOfflineHours <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(cfg.UnarchivedOfflineHours) * time.Hour)
	assets, err := st.ListAssets(model.AssetUnarchived)
	if err != nil {
		return
	}
	removed := 0
	for _, a := range assets {
		if a.LastSeen.After(cutoff) {
			continue
		}
		eng.RemoveNodeByKey(a.NodeKey)
		_ = st.DeleteAsset(a.NodeKey)
		_, _ = st.DeletePortsByKey(a.NodeKey)
		_, _ = st.AddAuditLog(&model.AuditLog{
			Actor: "system", Action: "asset_offline_cleanup", Target: a.NodeKey,
			Detail: fmt.Sprintf("账外资产离线超 %d 小时，自动清理（IP: %s）", cfg.UnarchivedOfflineHours, strings.Join(a.IPs, ",")),
		})
		removed++
	}
	if removed > 0 {
		slog.Info("清理离线账外资产", "removed", removed, "offline_hours", cfg.UnarchivedOfflineHours)
	}
}

// mergeRuntimeConfig 运行时保存的配置覆盖文件配置。
//
// 约定：**凡是通过 PUT /api/config 能被改的字段，这里都必须恢复**。
// 否则会出现「后台改完 → 运行正常 → 重启后又变回去」这种最难查的问题。
// 数值字段一律按「>0 才覆盖」处理，保住"零值 = 未设置"的语义；
// bool 字段没有"未设置"语义，所以显式覆盖。
func mergeRuntimeConfig(cfg, saved *model.SystemConfig) {
	if saved.AgingSeconds > 0 {
		cfg.AgingSeconds = saved.AgingSeconds
	}
	if saved.AggregateThreshold > 0 {
		cfg.AggregateThreshold = saved.AggregateThreshold
	}
	if saved.NoiseBytes > 0 {
		cfg.NoiseBytes = saved.NoiseBytes
	}
	if saved.NoisePackets > 0 {
		cfg.NoisePackets = saved.NoisePackets
	}
	if saved.NoiseDurationSec > 0 {
		cfg.NoiseDurationSec = saved.NoiseDurationSec
	}
	if saved.ReverseProxyHosts > 0 {
		cfg.ReverseProxyHosts = saved.ReverseProxyHosts
	}
	if saved.LongConnSeconds > 0 {
		cfg.LongConnSeconds = saved.LongConnSeconds
	}
	if saved.HeartbeatMaxBytes > 0 {
		cfg.HeartbeatMaxBytes = saved.HeartbeatMaxBytes
	}
	if saved.CaptureInterfaces != nil {
		cfg.CaptureInterfaces = saved.CaptureInterfaces
	}
	if saved.CaptureBPF != "" {
		cfg.CaptureBPF = saved.CaptureBPF
	}
	if saved.ProbeToken != "" {
		cfg.ProbeToken = saved.ProbeToken
	}
	if saved.AuditRetentionDays > 0 {
		cfg.AuditRetentionDays = saved.AuditRetentionDays
	}
	// 主机资产库（V1.2）
	if saved.UnarchivedOfflineHours > 0 {
		cfg.UnarchivedOfflineHours = saved.UnarchivedOfflineHours
	}
	if saved.ArchiveOfflineSeconds > 0 {
		cfg.ArchiveOfflineSeconds = saved.ArchiveOfflineSeconds
	}
	// 主动扫描（V1.2）
	if saved.ScanPorts != "" {
		cfg.ScanPorts = saved.ScanPorts
	}
	if saved.ScanRate != "" {
		cfg.ScanRate = saved.ScanRate
	}
	// 自动发现（V1.4 / V1.5）
	if saved.AutoDiscoverySec > 0 {
		cfg.AutoDiscoverySec = saved.AutoDiscoverySec
	}
	if saved.AutoDiscoveryCIDRs != nil {
		cfg.AutoDiscoveryCIDRs = saved.AutoDiscoveryCIDRs
	}
	if saved.AutoDiscoveryMethod != "" {
		cfg.AutoDiscoveryMethod = saved.AutoDiscoveryMethod
	}
	if saved.AutoDiscoveryExcludeCIDRs != nil {
		cfg.AutoDiscoveryExcludeCIDRs = saved.AutoDiscoveryExcludeCIDRs
	}
	if saved.AutoDiscoveryMaxCIDRs > 0 {
		cfg.AutoDiscoveryMaxCIDRs = saved.AutoDiscoveryMaxCIDRs
	}
	// 会话表容量治理（V1.0）
	if saved.SessionMaxCount > 0 {
		cfg.SessionMaxCount = saved.SessionMaxCount
	}
	if saved.SessionIdleSeconds > 0 {
		cfg.SessionIdleSeconds = saved.SessionIdleSeconds
	}
	if saved.SessionMaxAgeSeconds > 0 {
		cfg.SessionMaxAgeSeconds = saved.SessionMaxAgeSeconds
	}
	// 开关项
	cfg.ProbeEnabled = saved.ProbeEnabled
	cfg.CaptureEnabled = saved.CaptureEnabled
	cfg.AutoDiscoveryEnabled = saved.AutoDiscoveryEnabled
	cfg.AutoDiscoveryFollowDiscovered = saved.AutoDiscoveryFollowDiscovered
	// 可观测性（V1.0）
	//
	// 只恢复"后台可改"的三项。metrics_enabled 故意不恢复：
	// 它决定 /metrics 路由与 Registry 是否创建，属于**启动期**开关，运行时改了也不生效，
	// 恢复它只会造成"上次点过关，这次看着是关的但实际在跑"的错觉——以配置文件为准。
	if saved.LogLevel != "" {
		cfg.LogLevel = saved.LogLevel
	}
	if saved.LogFormat != "" {
		cfg.LogFormat = saved.LogFormat
	}
	if saved.MetricsToken != "" {
		cfg.MetricsToken = saved.MetricsToken
	}
}

// ---------- 自动发现：扫描目标计算（V1.5 新网段自动识别） ----------

// buildScanTargets 计算本轮扫描目标：
//  1. 配置的固定网段（auto_discovery_cidrs）
//  2. follow_discovered 开启时，追加流量已发现的全部内网 /24 网段
//
// 三重防误扫约束：仅内网（Engine.Subnets 只含内网 /24）、排除列表、单轮上限。
// 首次纳入的网段会打「发现新网段」日志，便于审计。
func buildScanTargets(cfg model.SystemConfig, eng *topology.Engine, maxN int, known map[string]bool) []string {
	out := make([]string, 0, 16)
	seen := map[string]bool{}

	add := func(cidr string) {
		if cidr == "" || seen[cidr] || len(out) >= maxN {
			return
		}
		if isExcludedCIDR(cidr, cfg.AutoDiscoveryExcludeCIDRs) {
			return
		}
		seen[cidr] = true
		out = append(out, cidr)
		if !known[cidr] {
			known[cidr] = true
			slog.Info("发现新网段，已纳入扫描", "cidr", cidr)
		}
	}

	for _, c := range cfg.AutoDiscoveryCIDRs {
		add(c)
	}
	if cfg.AutoDiscoveryFollowDiscovered && eng != nil {
		for _, s := range eng.Subnets() {
			add(s.CIDR)
		}
	}
	if len(out) >= maxN {
		slog.Warn("扫描目标已达单轮上限，其余网段本轮跳过", "max_cidrs", maxN)
	}
	return out
}

// isExcludedCIDR 判断 cidr 是否落在排除列表内（支持 CIDR 包含关系，如排除 /16 覆盖其下 /24）。
func isExcludedCIDR(cidr string, excludes []string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, ex := range excludes {
		_, exNet, err := net.ParseCIDR(strings.TrimSpace(ex))
		if err != nil {
			continue
		}
		if exNet.Contains(ip) {
			return true
		}
	}
	return false
}
