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
	if cfg.AgingSeconds != 86400 || cfg.AggregateThreshold != 20 || cfg.ListenAddr != ":8080" {
		t.Fatalf("默认值异常: %+v", cfg)
	}
	if cfg.ProbeEnabled || cfg.CaptureEnabled {
		t.Fatal("探测/抓包默认应关闭")
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
