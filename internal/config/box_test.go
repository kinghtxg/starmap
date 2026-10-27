package config

import (
	"errors"
	"sync"
	"testing"

	"starmap/internal/model"
)

// TestBoxGetReturnsCopy 读到的必须是副本：改副本不能影响容器。
func TestBoxGetReturnsCopy(t *testing.T) {
	box := NewBox(model.SystemConfig{AgingSeconds: 100, ProbeEnabled: true})

	got := box.Get()
	got.AgingSeconds = 999
	got.ProbeEnabled = false

	again := box.Get()
	if again.AgingSeconds != 100 {
		t.Fatalf("副本被改写穿透到本体：aging_seconds = %d，期望 100", again.AgingSeconds)
	}
	if !again.ProbeEnabled {
		t.Fatal("副本改 probe_enabled 穿透到本体")
	}
}

// TestBoxGetCopiesSlices 专门盯 slice：结构体拷贝是浅拷贝，
// 忘了深拷贝时 append 通常看不出来，但按下标改写会直接穿透。
func TestBoxGetCopiesSlices(t *testing.T) {
	box := NewBox(model.SystemConfig{
		CaptureInterfaces:         []string{"eth0", "eth1"},
		CorsOrigins:               []string{"https://a.example"},
		TrustedProxies:            []string{"10.0.0.0/8"},
		DiscoverCIDRs:             []string{"192.168.1.0/24"},
		AutoDiscoveryCIDRs:        []string{"172.16.0.0/12"},
		AutoDiscoveryExcludeCIDRs: []string{"172.16.9.0/24"},
	})

	got := box.Get()
	got.CaptureInterfaces[0] = "hacked"
	got.CorsOrigins[0] = "hacked"
	got.TrustedProxies[0] = "hacked"
	got.DiscoverCIDRs[0] = "hacked"
	got.AutoDiscoveryCIDRs[0] = "hacked"
	got.AutoDiscoveryExcludeCIDRs[0] = "hacked"

	fresh := box.Get()
	checks := []struct {
		name string
		got  string
	}{
		{"capture_interfaces", fresh.CaptureInterfaces[0]},
		{"cors_origins", fresh.CorsOrigins[0]},
		{"trusted_proxies", fresh.TrustedProxies[0]},
		{"discover_cidrs", fresh.DiscoverCIDRs[0]},
		{"auto_discovery_cidrs", fresh.AutoDiscoveryCIDRs[0]},
		{"auto_discovery_exclude_cidrs", fresh.AutoDiscoveryExcludeCIDRs[0]},
	}
	for _, c := range checks {
		if c.got == "hacked" {
			t.Fatalf("%s 的 slice 与本体共享底层数组（副本改写穿透）", c.name)
		}
	}
}

// TestBoxAuthSlicesCopied auth.Config 内嵌在 SystemConfig 里，容易被漏掉。
// 必须用非空初始值：nil slice 的 append 无论如何都会新分配，测不出穿透。
func TestBoxAuthSlicesCopied(t *testing.T) {
	base := model.SystemConfig{}
	base.Auth.PublicPaths = []string{"/health"}
	base.Auth.OIDC.Scopes = []string{"openid"}
	box := NewBox(base)

	got := box.Get()
	got.Auth.PublicPaths[0] = "/hacked"
	got.Auth.OIDC.Scopes[0] = "hacked"

	if v := box.Get().Auth.PublicPaths[0]; v != "/health" {
		t.Fatalf("auth.public_paths 被穿透：本体变成 %q", v)
	}
	if v := box.Get().Auth.OIDC.Scopes[0]; v != "openid" {
		t.Fatalf("auth.oidc.scopes 被穿透：本体变成 %q", v)
	}
}

// TestBoxUpdateApplies 正常修改要生效。
func TestBoxUpdateApplies(t *testing.T) {
	box := NewBox(model.SystemConfig{AgingSeconds: 10})
	snap, err := box.Update(func(c *model.SystemConfig) error {
		c.AgingSeconds = 20
		c.ProbeEnabled = true
		return nil
	})
	if err != nil {
		t.Fatalf("Update 返回错误: %v", err)
	}
	if snap.AgingSeconds != 20 || !snap.ProbeEnabled {
		t.Fatalf("返回值未反映修改: %+v", snap)
	}
	if got := box.Get(); got.AgingSeconds != 20 || !got.ProbeEnabled {
		t.Fatalf("容器未更新: %+v", got)
	}
}

// TestBoxUpdateRollsBack 闭包返回 error 时，本次修改必须整体丢弃。
//
// 这是 PUT /api/config 最需要的语义：改了 30 个字段，第 31 个非法，
// 不能留下"前 30 个已生效、没落盘、重启又变回去"的状态。
func TestBoxUpdateRollsBack(t *testing.T) {
	box := NewBox(model.SystemConfig{AgingSeconds: 10, ProbeEnabled: false})
	boom := errors.New("字段非法")

	snap, err := box.Update(func(c *model.SystemConfig) error {
		c.AgingSeconds = 99
		c.ProbeEnabled = true
		c.CaptureInterfaces = []string{"eth9"}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("期望拿到闭包的 error，实际 %v", err)
	}
	if snap.AgingSeconds != 10 {
		t.Fatalf("返回值应是回滚后的旧配置，实际 aging_seconds=%d", snap.AgingSeconds)
	}
	got := box.Get()
	if got.AgingSeconds != 10 || got.ProbeEnabled || len(got.CaptureInterfaces) != 0 {
		t.Fatalf("修改未回滚: %+v", got)
	}
}

// TestBoxNilSafe 测试里常常不构造 Cfg，nil 不能 panic。
func TestBoxNilSafe(t *testing.T) {
	var box *Box
	if got := box.Get(); got.AgingSeconds != 0 {
		t.Fatalf("nil Box 应返回零值，实际 %+v", got)
	}
	if _, err := box.Update(func(*model.SystemConfig) error { return nil }); err != nil {
		t.Fatalf("nil Box Update 不应报错: %v", err)
	}
	box.Set(model.SystemConfig{AgingSeconds: 1}) // 不应 panic
}

// TestBoxConcurrentAccess 并发读写不该崩、不该丢更新。
// 真正验证数据竞争需要 -race（CI 三平台跑）。
func TestBoxConcurrentAccess(t *testing.T) {
	box := NewBox(model.SystemConfig{AgingSeconds: 1})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = box.Update(func(c *model.SystemConfig) error {
					c.AgingSeconds = int64(n*1000 + j)
					c.CaptureInterfaces = append(c.CaptureInterfaces, "x")
					return nil
				})
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cfg := box.Get()
				_ = len(cfg.CaptureInterfaces)
				_ = cfg.AgingSeconds
			}
		}()
	}
	wg.Wait()

	// 每次 Update 都 append 一个元素，最终条数必须等于 Update 次数（无丢失更新）
	if n, want := len(box.Get().CaptureInterfaces), 8*200; n != want {
		t.Fatalf("并发 Update 丢更新：capture_interfaces=%d，期望 %d", n, want)
	}
}
