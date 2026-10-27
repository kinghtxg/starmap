// Package config 负责加载 configs/config.yaml 并填充默认值。
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"starmap/internal/auth"
	"starmap/internal/model"
)

// Default 返回内置默认配置。
func Default() model.SystemConfig {
	return model.SystemConfig{
		ProbeEnabled:       false,
		CaptureEnabled:     false,
		CaptureInterfaces:  []string{},
		CaptureBPF:         "",
		AgingSeconds:       86400,            // SPEC §4：边老化默认 86400 秒
		AggregateThreshold: 20,               // SPEC §4：/24 聚合阈值默认 20
		NoiseBytes:         400,              // SPEC §10.3：会话字节 < 400B 且短且少包 → 降噪
		NoisePackets:       4,                // SPEC §4：包数 < 4
		NoiseDurationSec:   2,                // SPEC §4：持续 < 2s
		ReverseProxyHosts:  10,               // SPEC §5：反代 Host 域名数阈值
		LongConnSeconds:    3600,             // SPEC §5：长连接 > 1h
		HeartbeatMaxBytes:  64,               // SPEC §5：心跳 payload < 64B
		ListenAddr:         "127.0.0.1:8080", // P0-4：默认仅回环，对外请走反代
		DBPath:             "starmap.db",
		ProbeToken:         "",  // §10.7：默认不校验
		AuditRetentionDays: 90,  // §10.8：审计日志保留 90 天
		EventRetentionDays: 180, // 风险事件保留 180 天（只清已处置的）
		Auth:               auth.Default(),
		// 主机资产库（V1.2）
		UnarchivedOfflineHours: 72,  // 未归档主机离线 72h 自动清理
		ArchiveOfflineSeconds:  600, // 归档主机 last_seen 超 10min 判离线
		// 会话表容量治理（V1.0）
		SessionMaxCount:      200000,    // 20 万条会话上限
		SessionIdleSeconds:   300,       // 静默 5 分钟回收
		SessionMaxAgeSeconds: 21600,     // 单会话最长 6 小时
		NmapPath:             "",        // 默认 "nmap"，空则运行时按 "nmap" 探测
		ScanPorts:            "1-65535", // 主动扫描默认全端口
		ScanRate:             "T4",      // 扫描速率
		// 可观测性（V1.0）
		LogLevel:       "info", // debug|info|warn|error
		LogFormat:      "text", // text 便于人工排查；生产建议 json（便于日志平台采集）
		MetricsEnabled: true,   // /metrics 默认开启，但默认只放行 admin 会话或抓取令牌
		MetricsToken:   "",
		// 自动发现（V1.4）：默认关闭，政务网等隔离环境需显式开启后才主动发包
		AutoDiscoveryEnabled: false,
		AutoDiscoverySec:     1800, // 30 分钟
		AutoDiscoveryCIDRs:   nil,
		AutoDiscoveryMethod:  "arp",
		// V1.5：新网段自动跟随。默认关闭；默认排除链路本地网段
		AutoDiscoveryFollowDiscovered: false,
		AutoDiscoveryExcludeCIDRs:     []string{"169.254.0.0/16"},
		AutoDiscoveryMaxCIDRs:         64,
		// 主动发现（1.2）：内置 TCP 扫描 + 服务指纹。
		// 默认关闭（与 auto_discovery 一致：隔离环境必须先明确授权才发包）；
		// 但一旦开启，默认档位取 quick 而不是 full——先让用户看到 "100 个端口 30 秒出结果"，
		// 再自己决定要不要上全端口，比默认全端口把内网扫一遍更负责。
		DiscoverEnabled:     false,
		DiscoverProfile:     "quick",
		DiscoverRatePPS:     800,
		DiscoverConcurrency: 256,
		DiscoverTimeoutMS:   800,
		DiscoverFingerprint: true,
		DiscoverMaxFP:       32,
		DiscoverWindow:      "",
		DiscoverSec:         0,
	}
}

// Load 从指定路径加载配置；文件不存在时返回默认配置。
// 未设置或零值的字段保留默认值。
func Load(path string) (model.SystemConfig, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // 无配置文件，使用默认值
		}
		return cfg, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var fileCfg model.SystemConfig
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("解析配置文件失败: %w", err)
	}
	// 默认值为 true 的开关无法用零值判断"是否显式配置过"，
	// 因此额外解析一份 key 集合：只有文件里真写了 metrics_enabled: false 才关掉它。
	var keys map[string]any
	_ = yaml.Unmarshal(data, &keys)
	_, hasMetricsEnabled := keys["metrics_enabled"]
	_, hasDiscoverFingerprint := keys["discover_fingerprint"]
	// 合并：仅覆盖显式设置的字段（零值字段保留默认）
	if fileCfg.CaptureInterfaces != nil {
		cfg.CaptureInterfaces = fileCfg.CaptureInterfaces
	}
	if fileCfg.CaptureBPF != "" {
		cfg.CaptureBPF = fileCfg.CaptureBPF
	}
	if fileCfg.ListenAddr != "" {
		cfg.ListenAddr = fileCfg.ListenAddr
	}
	if fileCfg.DBPath != "" {
		cfg.DBPath = fileCfg.DBPath
	}
	if fileCfg.ProbeToken != "" {
		cfg.ProbeToken = fileCfg.ProbeToken
	}
	if fileCfg.AuditRetentionDays != 0 {
		cfg.AuditRetentionDays = fileCfg.AuditRetentionDays
	}
	if fileCfg.EventRetentionDays != 0 {
		cfg.EventRetentionDays = fileCfg.EventRetentionDays
	}
	if fileCfg.CorsOrigins != nil {
		cfg.CorsOrigins = fileCfg.CorsOrigins
	}
	if fileCfg.TrustedProxies != nil {
		cfg.TrustedProxies = fileCfg.TrustedProxies
	}
	if fileCfg.UnarchivedOfflineHours != 0 {
		cfg.UnarchivedOfflineHours = fileCfg.UnarchivedOfflineHours
	}
	if fileCfg.ArchiveOfflineSeconds != 0 {
		cfg.ArchiveOfflineSeconds = fileCfg.ArchiveOfflineSeconds
	}
	// 会话表容量治理（V1.0）
	if fileCfg.SessionMaxCount != 0 {
		cfg.SessionMaxCount = fileCfg.SessionMaxCount
	}
	if fileCfg.SessionIdleSeconds != 0 {
		cfg.SessionIdleSeconds = fileCfg.SessionIdleSeconds
	}
	if fileCfg.SessionMaxAgeSeconds != 0 {
		cfg.SessionMaxAgeSeconds = fileCfg.SessionMaxAgeSeconds
	}
	if fileCfg.NmapPath != "" {
		cfg.NmapPath = fileCfg.NmapPath
	}
	// 可观测性（V1.0）
	if fileCfg.LogLevel != "" {
		cfg.LogLevel = fileCfg.LogLevel
	}
	if fileCfg.LogFormat != "" {
		cfg.LogFormat = fileCfg.LogFormat
	}
	if hasMetricsEnabled {
		cfg.MetricsEnabled = fileCfg.MetricsEnabled
	}
	if fileCfg.MetricsToken != "" {
		cfg.MetricsToken = fileCfg.MetricsToken
	}
	if fileCfg.ScanPorts != "" {
		cfg.ScanPorts = fileCfg.ScanPorts
	}
	if fileCfg.ScanRate != "" {
		cfg.ScanRate = fileCfg.ScanRate
	}
	// 自动发现（V1.4）
	if fileCfg.AutoDiscoveryEnabled {
		cfg.AutoDiscoveryEnabled = true
	}
	if fileCfg.AutoDiscoverySec != 0 {
		cfg.AutoDiscoverySec = fileCfg.AutoDiscoverySec
	}
	if len(fileCfg.AutoDiscoveryCIDRs) > 0 {
		cfg.AutoDiscoveryCIDRs = fileCfg.AutoDiscoveryCIDRs
	}
	if fileCfg.AutoDiscoveryMethod != "" {
		cfg.AutoDiscoveryMethod = fileCfg.AutoDiscoveryMethod
	}
	// V1.5 新网段自动跟随
	if fileCfg.AutoDiscoveryFollowDiscovered {
		cfg.AutoDiscoveryFollowDiscovered = true
	}
	if len(fileCfg.AutoDiscoveryExcludeCIDRs) > 0 {
		cfg.AutoDiscoveryExcludeCIDRs = fileCfg.AutoDiscoveryExcludeCIDRs
	}
	if fileCfg.AutoDiscoveryMaxCIDRs != 0 {
		cfg.AutoDiscoveryMaxCIDRs = fileCfg.AutoDiscoveryMaxCIDRs
	}
	// 主动发现（1.2）
	if fileCfg.DiscoverEnabled {
		cfg.DiscoverEnabled = true
	}
	if fileCfg.DiscoverProfile != "" {
		cfg.DiscoverProfile = fileCfg.DiscoverProfile
	}
	if fileCfg.DiscoverRatePPS != 0 {
		cfg.DiscoverRatePPS = fileCfg.DiscoverRatePPS
	}
	if fileCfg.DiscoverConcurrency != 0 {
		cfg.DiscoverConcurrency = fileCfg.DiscoverConcurrency
	}
	if fileCfg.DiscoverTimeoutMS != 0 {
		cfg.DiscoverTimeoutMS = fileCfg.DiscoverTimeoutMS
	}
	// 默认 true 的开关同样只能靠"文件里有没有这个键"判断（写 false 才真关）
	if hasDiscoverFingerprint {
		cfg.DiscoverFingerprint = fileCfg.DiscoverFingerprint
	}
	if fileCfg.DiscoverMaxFP != 0 {
		cfg.DiscoverMaxFP = fileCfg.DiscoverMaxFP
	}
	if fileCfg.DiscoverWindow != "" {
		cfg.DiscoverWindow = fileCfg.DiscoverWindow
	}
	if fileCfg.DiscoverSec != 0 {
		cfg.DiscoverSec = fileCfg.DiscoverSec
	}
	if len(fileCfg.DiscoverCIDRs) > 0 {
		cfg.DiscoverCIDRs = fileCfg.DiscoverCIDRs
	}
	if fileCfg.AgingSeconds != 0 {
		cfg.AgingSeconds = fileCfg.AgingSeconds
	}
	if fileCfg.AggregateThreshold != 0 {
		cfg.AggregateThreshold = fileCfg.AggregateThreshold
	}
	if fileCfg.NoiseBytes != 0 {
		cfg.NoiseBytes = fileCfg.NoiseBytes
	}
	if fileCfg.NoisePackets != 0 {
		cfg.NoisePackets = fileCfg.NoisePackets
	}
	if fileCfg.NoiseDurationSec != 0 {
		cfg.NoiseDurationSec = fileCfg.NoiseDurationSec
	}
	if fileCfg.ReverseProxyHosts != 0 {
		cfg.ReverseProxyHosts = fileCfg.ReverseProxyHosts
	}
	if fileCfg.LongConnSeconds != 0 {
		cfg.LongConnSeconds = fileCfg.LongConnSeconds
	}
	if fileCfg.HeartbeatMaxBytes != 0 {
		cfg.HeartbeatMaxBytes = fileCfg.HeartbeatMaxBytes
	}
	// 布尔开关直接采用文件值（默认均为 false）
	cfg.ProbeEnabled = fileCfg.ProbeEnabled
	cfg.CaptureEnabled = fileCfg.CaptureEnabled
	// 可选账号系统 / APSSO（K2）：结构体字段靠 auth.Merge 逐项判空合并。
	//
	// 这一行曾经缺失，后果是「在 config.yaml 里写 auth.mode: local 完全没用，
	// 服务照旧以 mode=none 裸奔，而且没有任何报错」——静默失效的开关比没有开关更危险。
	cfg.Auth = auth.Merge(cfg.Auth, fileCfg.Auth)
	return cfg, nil
}
