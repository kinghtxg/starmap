package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AgingSeconds != 86400 || cfg.AggregateThreshold != 20 || cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("默认值异常: %+v", cfg)
	}
	if cfg.ProbeEnabled || cfg.CaptureEnabled {
		t.Fatal("探测/抓包默认应关闭")
	}
	if cfg.Auth.Mode != "none" {
		t.Fatalf("认证默认应关闭(none): %q", cfg.Auth.Mode)
	}
}

func TestLoadOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("aging_seconds: 3600\ncapture_enabled: true\ncapture_interfaces: [eth0]\n"), 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AgingSeconds != 3600 {
		t.Fatalf("覆盖失败: %d", cfg.AgingSeconds)
	}
	if !cfg.CaptureEnabled || len(cfg.CaptureInterfaces) != 1 {
		t.Fatalf("布尔/列表覆盖失败: %+v", cfg)
	}
	if cfg.AggregateThreshold != 20 {
		t.Fatalf("未设置字段应保留默认值: %d", cfg.AggregateThreshold)
	}
}

// V1.4 自动发现：默认关闭（隔离环境不主动发包），显式开启后加载配置
func TestAutoDiscoveryDefaultsAndOverride(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AutoDiscoveryEnabled {
		t.Fatal("自动发现默认必须关闭")
	}
	if cfg.AutoDiscoverySec != 1800 || cfg.AutoDiscoveryMethod != "arp" {
		t.Fatalf("自动发现默认值异常: sec=%d method=%q", cfg.AutoDiscoverySec, cfg.AutoDiscoveryMethod)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`auto_discovery_enabled: true
auto_discovery_sec: 300
auto_discovery_method: icmp
auto_discovery_cidrs: ["10.10.1.0/24","172.16.5.0/24"]
`), 0o644)
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AutoDiscoveryEnabled || cfg.AutoDiscoverySec != 300 || cfg.AutoDiscoveryMethod != "icmp" {
		t.Fatalf("自动发现覆盖失败: %+v", cfg)
	}
	if len(cfg.AutoDiscoveryCIDRs) != 2 || cfg.AutoDiscoveryCIDRs[0] != "10.10.1.0/24" {
		t.Fatalf("网段列表覆盖失败: %v", cfg.AutoDiscoveryCIDRs)
	}
}
