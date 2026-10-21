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
		ProbeToken:         "", // §10.7：默认不校验
		AuditRetentionDays: 90, // §10.8：审计日志保留 90 天
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
		// 自动发现（V1.4）：默认关闭，政务网等隔离环境需显式开启后才主动发包
		AutoDiscoveryEnabled: false,
		AutoDiscoverySec:     1800, // 30 分钟
		AutoDiscoveryCIDRs:   nil,
		AutoDiscoveryMethod:  "arp",
		// V1.5：新网段自动跟随。默认关闭；默认排除链路本地网段
		AutoDiscoveryFollowDiscovered: false,
		AutoDiscoveryExcludeCIDRs:     []string{"169.254.0.0/16"},
		AutoDiscoveryMaxCIDRs:         64,
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
	if fileCfg.CorsOrigins != nil {
		cfg.CorsOrigins = fileCfg.CorsOrigins
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
	return cfg, nil
}
