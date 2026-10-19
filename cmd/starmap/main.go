// StarMap 星图 V1.0 入口：装配 config → store → engine → detector → review → api，
// 抓包/PCAP导入/探针三路 PacketSource 汇入 Aggregator → Engine；优雅退出。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"starmap/internal/api"
	"starmap/internal/config"
	"starmap/internal/detect"
	"starmap/internal/ingest"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// 默认预置网络域（ACCEPTANCE 8.1）
var defaultDomains = []model.NetDomain{
	{Name: "gov", CIDRs: []string{"10.0.0.0/8"}, Color: "#38BDF8"},
	{Name: "office", CIDRs: []string{"172.16.0.0/12"}, Color: "#4ADE80"},
	{Name: "internet", CIDRs: []string{"0.0.0.0/0"}, Color: "#94A3B8"},
	{Name: "prod", CIDRs: []string{"192.168.0.0/16"}, Color: "#FB923C"},
}

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "配置文件路径")
	flag.Parse()

	// 1. 配置
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	// 1.1 校验可选账号系统 / APSSO 配置（默认 none，永远合法）
	if err := cfg.Auth.Validate(); err != nil {
		log.Fatalf("认证配置非法: %v", err)
	}

	// 2. 存储
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
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
				log.Printf("预置网络域 %s 失败: %v", d.Name, err)
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
		log.Fatalf("恢复拓扑失败: %v", err)
	}
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)

	// 4. 检测调度器 + 复核 + 探测器
	det := detect.New(st, engine, cfg)
	det.SessionsFunc = agg.Finalize
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
						log.Printf("[audit] 清理 %d 条超期审计日志", n)
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
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, ses := range agg.Finalize() {
					s := ses
					engine.Ingest(&s)
				}
			}
		}
	}()
	// 自动发现（V1.4）：周期性对目标网段做主动扫描，让拓扑"自生长"。
	// 默认关闭；需同时开启 probe_enabled（主动探测总开关）与 auto_discovery_enabled。
	if cfg.AutoDiscoveryEnabled && len(cfg.AutoDiscoveryCIDRs) > 0 {
		interval := time.Duration(cfg.AutoDiscoverySec) * time.Second
		if interval <= 0 {
			interval = 30 * time.Minute
		}
		method := cfg.AutoDiscoveryMethod
		if method == "" {
			method = "arp"
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			log.Printf("[auto-discovery] 已启用：每 %v 对 %d 个网段做 %s 扫描",
				interval, len(cfg.AutoDiscoveryCIDRs), method)
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for _, cidr := range cfg.AutoDiscoveryCIDRs {
						res, err := scanner.Trigger(method, cidr)
						if err != nil {
							log.Printf("[auto-discovery] %s %s 失败: %v", method, cidr, err)
							continue
						}
						if res != nil && len(res.Hosts) > 0 {
							log.Printf("[auto-discovery] %s %s 发现 %d 台主机",
								method, cidr, len(res.Hosts))
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
			log.Printf("[capture] 启动失败: %v", err)
		} else {
			go func() {
				for p := range src {
					agg.Ingest(p)
				}
			}()
			log.Printf("[capture] 已启动: %v", cfg.CaptureInterfaces)
		}
	}

	// 6. API 服务
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
		Version: "V1.2",
	})

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv}
	go func() {
		log.Printf("StarMap 星图 V1.0 就绪 | listen=%s db=%s capture=%v probe=%v",
			cfg.ListenAddr, cfg.DBPath, cfg.CaptureEnabled, cfg.ProbeEnabled)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务失败: %v", err)
		}
	}()

	// 7. 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("正在优雅退出...")
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	_ = httpSrv.Shutdown(shCtx)
	det.Stop()
	// 退出前落盘全部会话 + 拓扑
	for _, ses := range agg.Finalize() {
		s := ses
		_, _ = st.SaveSession(&s)
	}
	if err := engine.Flush(); err != nil {
		log.Printf("[topology] 退出前拓扑落盘失败: %v", err)
	}
	log.Println("已退出")
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
		log.Printf("[assets] 清理 %d 台离线账外资产", removed)
	}
}

// mergeRuntimeConfig 运行时保存的配置覆盖文件配置。
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
	cfg.ProbeEnabled = saved.ProbeEnabled
	cfg.CaptureEnabled = saved.CaptureEnabled
}
