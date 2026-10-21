package main

import (
	"testing"

	"starmap/internal/config"
	"starmap/internal/model"
)

// mergeRuntimeConfig 是「运行时配置覆盖文件配置」的唯一入口。
// 它错了会导致：后台改的设置重启后失效，或反过来把配置文件里的值吃掉。
func TestMergeRuntimeConfig(t *testing.T) {
	base := config.Default()
	saved := model.SystemConfig{
		AgingSeconds:       7200,
		AggregateThreshold: 50,
		NoiseBytes:         800,
		NoisePackets:       8,
		NoiseDurationSec:   5,
		ReverseProxyHosts:  20,
		LongConnSeconds:    1800,
		HeartbeatMaxBytes:  128,
		CaptureInterfaces:  []string{"eth1"},
		CaptureBPF:         "tcp port 80",
		ProbeToken:         "secret",
		AuditRetentionDays: 30,
		ProbeEnabled:       true,
		CaptureEnabled:     true,
		// 扫描与自动发现（曾经"改了重启就丢"的一批字段）
		ScanPorts:                     "1-1024",
		ScanRate:                      "T3",
		AutoDiscoveryEnabled:          true,
		AutoDiscoverySec:              600,
		AutoDiscoveryMethod:           "icmp",
		AutoDiscoveryCIDRs:            []string{"10.10.1.0/24"},
		AutoDiscoveryFollowDiscovered: true,
		AutoDiscoveryMaxCIDRs:         8,
		AutoDiscoveryExcludeCIDRs:     []string{"10.10.9.0/24"},
		UnarchivedOfflineHours:        24,
		ArchiveOfflineSeconds:         300,
		// 会话表容量（V1.0）
		SessionMaxCount:      123,
		SessionIdleSeconds:   60,
		SessionMaxAgeSeconds: 600,
	}
	got := base
	mergeRuntimeConfig(&got, &saved)

	if got.AgingSeconds != 7200 || got.AggregateThreshold != 50 {
		t.Fatalf("基础参数未覆盖: %+v", got)
	}
	if got.NoiseBytes != 800 || got.NoisePackets != 8 || got.NoiseDurationSec != 5 {
		t.Fatalf("降噪参数未覆盖: %+v", got)
	}
	if got.LongConnSeconds != 1800 || got.HeartbeatMaxBytes != 128 {
		t.Fatalf("长连接参数未覆盖: %+v", got)
	}
	if len(got.CaptureInterfaces) != 1 || got.CaptureInterfaces[0] != "eth1" {
		t.Fatalf("抓包网卡未覆盖: %v", got.CaptureInterfaces)
	}
	if got.ProbeToken != "secret" || got.CaptureBPF != "tcp port 80" {
		t.Fatalf("探针/BPF 未覆盖: %+v", got)
	}
	if !got.ProbeEnabled || !got.CaptureEnabled {
		t.Fatal("开关项未覆盖（bool 必须显式覆盖，不能靠非零判断）")
	}
	if got.AuditRetentionDays != 30 {
		t.Fatalf("审计保留期未覆盖: %d", got.AuditRetentionDays)
	}
	// 下面这批是历史遗漏项：putConfig 会持久化，但启动时不恢复 = 改了重启就丢
	if got.ScanPorts != "1-1024" || got.ScanRate != "T3" {
		t.Fatalf("扫描参数未恢复: ports=%q rate=%q", got.ScanPorts, got.ScanRate)
	}
	if !got.AutoDiscoveryEnabled || got.AutoDiscoverySec != 600 || got.AutoDiscoveryMethod != "icmp" {
		t.Fatalf("自动发现参数未恢复: %+v", got)
	}
	if len(got.AutoDiscoveryCIDRs) != 1 || !got.AutoDiscoveryFollowDiscovered || got.AutoDiscoveryMaxCIDRs != 8 {
		t.Fatalf("自动发现网段/跟随未恢复: %+v", got)
	}
	if got.UnarchivedOfflineHours != 24 || got.ArchiveOfflineSeconds != 300 {
		t.Fatalf("资产离线阈值未恢复: %d / %d", got.UnarchivedOfflineHours, got.ArchiveOfflineSeconds)
	}
	if got.SessionMaxCount != 123 || got.SessionIdleSeconds != 60 || got.SessionMaxAgeSeconds != 600 {
		t.Fatalf("会话表容量未恢复: %+v", got)
	}
}

// 零值必须保留默认：否则用户在后台清空一个数字输入框，重启后会把配置清零（例如老化时间变成 0）。
func TestMergeRuntimeConfigKeepsDefaultsOnZero(t *testing.T) {
	base := config.Default()
	want := base
	mergeRuntimeConfig(&base, &model.SystemConfig{}) // 全零
	if base.AgingSeconds != want.AgingSeconds {
		t.Fatalf("零值不应覆盖默认老化时间: %d != %d", base.AgingSeconds, want.AgingSeconds)
	}
	if base.AggregateThreshold != want.AggregateThreshold {
		t.Fatalf("零值不应覆盖默认聚合阈值: %d != %d", base.AggregateThreshold, want.AggregateThreshold)
	}
	if base.SessionMaxCount != want.SessionMaxCount {
		t.Fatalf("零值不应覆盖默认会话上限: %d != %d", base.SessionMaxCount, want.SessionMaxCount)
	}
	// bool 是例外：开/关都要能被显式表达，所以零值=false 会覆盖
	if base.ProbeEnabled {
		t.Fatal("ProbeEnabled 零值应为 false（bool 无'未设置'语义）")
	}
}
