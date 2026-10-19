package main

import (
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/topology"
)

func TestIsExcludedCIDR(t *testing.T) {
	cases := []struct {
		cidr     string
		excludes []string
		want     bool
	}{
		{"169.254.1.0/24", []string{"169.254.0.0/16"}, true},
		{"10.10.1.0/24", []string{"169.254.0.0/16"}, false},
		{"192.168.1.0/24", []string{"192.168.0.0/16"}, true},
		{"192.168.1.0/24", nil, false},
		{"not-a-cidr", []string{"10.0.0.0/8"}, false},
	}
	for _, c := range cases {
		if got := isExcludedCIDR(c.cidr, c.excludes); got != c.want {
			t.Errorf("isExcludedCIDR(%q, %v) = %v, want %v", c.cidr, c.excludes, got, c.want)
		}
	}
}

// 未开启 follow：只用配置网段
func TestBuildScanTargetsWithoutFollow(t *testing.T) {
	cfg := model.SystemConfig{AutoDiscoveryCIDRs: []string{"10.10.1.0/24", "172.16.5.0/24"}}
	got := buildScanTargets(cfg, nil, 64, map[string]bool{})
	if len(got) != 2 {
		t.Fatalf("未开启 follow 时应只返回配置网段，实际 %v", got)
	}
}

// 开启 follow：配置网段 ∪ 已发现网段，且排除列表生效
func TestBuildScanTargetsFollowDiscovered(t *testing.T) {
	cfg := model.SystemConfig{
		AutoDiscoveryCIDRs:            []string{"10.10.1.0/24"},
		AutoDiscoveryFollowDiscovered: true,
		AutoDiscoveryExcludeCIDRs:     []string{"172.16.0.0/12"},
	}
	eng := topology.New(cfg)
	now := time.Now()
	eng.ObserveHost("10.10.1.5", "aa:bb:cc:00:00:01", now)
	eng.ObserveHost("10.20.1.5", "aa:bb:cc:00:00:02", now)
	eng.ObserveHost("172.16.5.5", "aa:bb:cc:00:00:03", now) // 命中排除列表，不应被扫

	got := buildScanTargets(cfg, eng, 64, map[string]bool{})
	set := map[string]bool{}
	for _, c := range got {
		set[c] = true
	}
	if !set["10.10.1.0/24"] {
		t.Fatalf("应包含配置网段 10.10.1.0/24，实际 %v", got)
	}
	if !set["10.20.1.0/24"] {
		t.Fatalf("应包含流量发现的 10.20.1.0/24（新网段自动识别），实际 %v", got)
	}
	if set["172.16.5.0/24"] {
		t.Fatalf("排除列表内网段不应被扫，实际 %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("去重后应为 2 个网段，实际 %d: %v", len(got), got)
	}
}

// 单轮上限生效
func TestBuildScanTargetsMaxLimit(t *testing.T) {
	cfg := model.SystemConfig{
		AutoDiscoveryCIDRs:            []string{"10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"},
		AutoDiscoveryFollowDiscovered: true,
	}
	got := buildScanTargets(cfg, nil, 2, map[string]bool{})
	if len(got) != 2 {
		t.Fatalf("上限 2 时应只返回 2 个，实际 %d: %v", len(got), got)
	}
}

// 新网段首次纳入时写入 known，第二轮不再重复记录（幂等）
func TestBuildScanTargetsKnownTracking(t *testing.T) {
	cfg := model.SystemConfig{AutoDiscoveryCIDRs: []string{"10.9.9.0/24"}}
	known := map[string]bool{}
	buildScanTargets(cfg, nil, 64, known)
	if !known["10.9.9.0/24"] {
		t.Fatal("首轮应把网段记入 known")
	}
	before := len(known)
	buildScanTargets(cfg, nil, 64, known)
	if len(known) != before {
		t.Fatal("第二轮不应重复记录")
	}
}
