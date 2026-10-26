package discover

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/probe"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// ---------- 辅助 ----------

func testCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
		DiscoverProfile:     probe.ProfileQuick,
		DiscoverConcurrency: 64,
		DiscoverTimeoutMS:   500,
		DiscoverRatePPS:     0, // 测试不限速
		DiscoverFingerprint: true,
		DiscoverMaxFP:       8,
	}
}

func newRunner(t *testing.T, cfg model.SystemConfig) (*Runner, *store.Store, *topology.Engine, *probe.Scanner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := topology.New(cfg)
	sc := probe.New(eng)
	sc.NowFunc = time.Now
	sc.SetRate(0)

	c := cfg // 快照
	r := &Runner{Store: st, Engine: eng, Scanner: sc, Cfg: func() model.SystemConfig { return c }}
	return r, st, eng, sc
}

func serverPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析地址失败: %v", err)
	}
	_, ps, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("拆分地址失败: %v", err)
	}
	p, _ := strconv.Atoi(ps)
	return p
}

// ---------- Options ----------

func TestOptionsMapping(t *testing.T) {
	cfg := testCfg()
	cfg.DiscoverWindow = "22:00-06:00"
	cfg.DiscoverFingerprint = false
	cfg.DiscoverRatePPS = 123
	r := &Runner{Cfg: func() model.SystemConfig { return cfg }}

	opt := r.Options("", nil)
	if opt.Profile != probe.ProfileQuick {
		t.Errorf("档位 = %q，应取配置里的 quick", opt.Profile)
	}
	if opt.Scan.Concurrency != 64 {
		t.Errorf("并发 = %d，期望 64", opt.Scan.Concurrency)
	}
	if opt.Scan.Timeout != 500*time.Millisecond {
		t.Errorf("超时 = %v，期望 500ms", opt.Scan.Timeout)
	}
	if opt.Scan.RatePPS != 123 {
		t.Errorf("速率 = %d，期望 123", opt.Scan.RatePPS)
	}
	if !opt.SkipFingerprint {
		t.Error("配置关闭指纹时应 SkipFingerprint=true")
	}
	if opt.MaxFingerprintPorts != 8 {
		t.Errorf("指纹端口上限 = %d，期望 8", opt.MaxFingerprintPorts)
	}
	if opt.Window == nil || !opt.Window.Contains(time.Date(2025, 1, 1, 23, 0, 0, 0, time.Local)) {
		t.Errorf("时间窗口未生效: %+v", opt.Window)
	}
}

func TestOptionsOverrides(t *testing.T) {
	cfg := testCfg()
	cfg.DiscoverFingerprint = false
	r := &Runner{Cfg: func() model.SystemConfig { return cfg }}

	yes := true
	if opt := r.Options("full", &yes); opt.Profile != probe.ProfileFull || opt.SkipFingerprint {
		t.Errorf("显式参数未生效: profile=%q skip=%v", opt.Profile, opt.SkipFingerprint)
	}
	no := false
	if opt := r.Options("", &no); !opt.SkipFingerprint {
		t.Error("显式关闭指纹未生效")
	}

	// 空窗口 / 非法窗口都不应带出 Window（否则会把扫描永久卡在"不在窗口内"）
	cfg.DiscoverWindow = ""
	if opt := r.Options("", nil); opt.Window != nil && !opt.Window.Contains(time.Now()) {
		t.Error("空窗口应为全天")
	}
	cfg.DiscoverWindow = "不是时间"
	if opt := r.Options("", nil); opt.Window != nil {
		t.Errorf("非法窗口应被忽略，实际 %+v", opt.Window)
	}
}

func TestOptionsKnownHost(t *testing.T) {
	cfg := testCfg()
	r, _, eng, _ := newRunner(t, cfg)

	if r.Options("", nil).Known == nil {
		t.Fatal("有拓扑引擎时应提供已知主机判定（用于降频）")
	}
	known := r.Options("", nil).Known
	if known("10.1.2.3") {
		t.Error("没见过的地址不应被判为已知")
	}
	eng.ObserveHost("10.1.2.3", "", time.Now())
	if !known("10.1.2.3") {
		t.Error("拓扑里已有的地址应被判为已知")
	}

	// 没有引擎时不应 panic（插件化装配可能不注入引擎）
	r2 := &Runner{Cfg: func() model.SystemConfig { return cfg }}
	if opt := r2.Options("", nil); opt.Known != nil {
		t.Error("无引擎时不应提供已知判定")
	}
}

// ---------- Run ----------

func TestRunPersistsPortsAndFeedsTopology(t *testing.T) {
	r, st, eng, _ := newRunner(t, testCfg())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte{1, 2, 3, 4})
			return
		}
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte(`<html><title>内网门户</title></html>`))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)

	opt := r.Options("", nil)
	opt.Ports = []int{port} // 只扫这一个端口，避免真扫 1-1024
	opt.Scan.Timeout = 500 * time.Millisecond
	opt.Fingerprint.FetchFavicon = true

	res, err := r.Run(context.Background(), []string{"127.0.0.1"}, opt, nil)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.Alive != 1 || res.OpenPorts != 1 || res.Fingerprints != 1 {
		t.Fatalf("结果汇总异常: alive=%d ports=%d fp=%d", res.Alive, res.OpenPorts, res.Fingerprints)
	}

	records, err := st.ListPorts("127.0.0.1", "")
	if err != nil {
		t.Fatalf("查询端口失败: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("应落库 1 条端口记录，实际 %d", len(records))
	}
	rec := records[0]
	if rec.Port != port || rec.Source != model.PortSourceProbe || rec.State != "open" {
		t.Errorf("端口记录异常: %+v", rec)
	}
	if rec.Product != "nginx" || rec.Version != "1.24.0" {
		t.Errorf("指纹未落库: product=%q version=%q", rec.Product, rec.Version)
	}
	if rec.Title != "内网门户" {
		t.Errorf("标题未落库: %q", rec.Title)
	}
	if rec.Favicon == "" {
		t.Error("favicon 哈希未落库")
	}
	if rec.NodeKey == "" {
		t.Error("应关联 node_key（主动发现的主机进入拓扑后才有键）")
	}
	if eng.NodeByIP("127.0.0.1") == nil {
		t.Error("活跃主机应进入拓扑（否则资产列表有、拓扑图上没有）")
	}
}

// 指纹写过的记录不能被后续"无指纹"的流量提取抹掉。
func TestRunKeepsFingerprintOnRewrite(t *testing.T) {
	r, st, eng, _ := newRunner(t, testCfg())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Server", "nginx/1.20.0")
		_, _ = w.Write([]byte(`<html><title>门户</title></html>`))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)

	opt := r.Options("", nil)
	opt.Ports = []int{port}
	opt.Scan.Timeout = 500 * time.Millisecond
	opt.Fingerprint.FetchFavicon = false
	if _, err := r.Run(context.Background(), []string{"127.0.0.1"}, opt, nil); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	// 模拟流量侧再写一次同一端口（无任何指纹信息）。
	// node_key 必须一致：ports 的唯一键是 (node_key,ip,port,proto)，
	// 流量侧在 ingest 时同样会按 IP 查节点键，这里保持一致才等价于真实路径。
	node := eng.NodeByIP("127.0.0.1")
	if node == nil {
		t.Fatal("发现后主机应已进入拓扑")
	}
	now := time.Now()
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: node.NodeKey, IP: "127.0.0.1", Port: port, Proto: "tcp",
		Source: model.PortSourceTraffic, State: "open", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	records, err := st.ListPorts("127.0.0.1", "")
	if err != nil || len(records) != 1 {
		t.Fatalf("记录数异常: %d / %v", len(records), err)
	}
	if records[0].Product != "nginx" {
		t.Errorf("指纹被空值覆盖了: product=%q", records[0].Product)
	}
	if records[0].Title != "门户" {
		t.Errorf("标题被空值覆盖了: %q", records[0].Title)
	}
}

func TestRunOutsideWindow(t *testing.T) {
	r, st, _, sc := newRunner(t, testCfg())
	// 固定时钟到 03:00，窗口设 09:00-18:00 → 确定性落在窗口外（不依赖跑测试的真实时刻）
	sc.NowFunc = func() time.Time { return time.Date(2025, 1, 1, 3, 0, 0, 0, time.Local) }

	w, err := probe.ParseWindow("09:00-18:00")
	if err != nil {
		t.Fatalf("解析窗口失败: %v", err)
	}
	opt := r.Options("", nil)
	opt.Ports = []int{80}
	opt.Window = &w

	_, err = r.Run(context.Background(), []string{"127.0.0.1"}, opt, nil)
	if !errors.Is(err, probe.ErrOutsideWindow) {
		t.Fatalf("窗口外应拒绝执行，实际 %v", err)
	}
	records, _ := st.ListPorts("", "")
	if len(records) != 0 {
		t.Errorf("窗口外不应落库任何记录，实际 %d 条", len(records))
	}
}

func TestRunWithoutScanner(t *testing.T) {
	r := &Runner{Cfg: func() model.SystemConfig { return testCfg() }}
	if _, err := r.Run(context.Background(), []string{"127.0.0.1"}, probe.DefaultDiscoverOptions(), nil); err == nil {
		t.Fatal("未初始化扫描器应报错而不是 panic")
	}
}

func TestRunContextCancel(t *testing.T) {
	r, st, _, sc := newRunner(t, testCfg())
	sc.SetEnabled(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opt := r.Options("", nil)
	opt.Ports = []int{80, 443}
	_, err := r.Run(ctx, []string{"10.255.255.1", "10.255.255.2"}, opt, nil)
	if err == nil {
		t.Fatal("已取消的上下文应返回错误")
	}
	records, _ := st.ListPorts("", "")
	if len(records) != 0 {
		t.Errorf("取消后不应落库，实际 %d 条", len(records))
	}
}

// ---------- 排序 ----------

func TestSortHostsByIPNumeric(t *testing.T) {
	hosts := []probe.HostResult{
		{IP: "10.0.0.10"}, {IP: "10.0.0.9"}, {IP: "10.0.0.2"}, {IP: "192.168.1.1"}, {IP: "10.0.1.1"},
	}
	SortHostsByIP(hosts)
	want := []string{"10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.1.1", "192.168.1.1"}
	for i, w := range want {
		if hosts[i].IP != w {
			t.Fatalf("第 %d 项 = %q，期望 %q（字符串排序会把 .10 排到 .9 前面）", i, hosts[i].IP, w)
		}
	}
	// 非 IPv4 输入不应 panic，且保持稳定
	odd := []probe.HostResult{{IP: "b"}, {IP: "a"}}
	SortHostsByIP(odd)
	if odd[0].IP != "a" {
		t.Errorf("非 IPv4 输入排序异常: %v", odd)
	}
}

func TestParseIPv4(t *testing.T) {
	ok := map[string][]int{
		"0.0.0.0":         {0, 0, 0, 0},
		"10.1.2.3":        {10, 1, 2, 3},
		"255.255.255.255": {255, 255, 255, 255},
	}
	for in, want := range ok {
		got := parseIPv4(in)
		if len(got) != 4 {
			t.Fatalf("parseIPv4(%q) = %v", in, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parseIPv4(%q)[%d] = %d，期望 %d", in, i, got[i], want[i])
			}
		}
	}
	for _, bad := range []string{"", "10.1.2", "10.1.2.3.4", "10..2.3", "a.b.c.d", "256.1.1.1", "10.1.2.-3"} {
		if got := parseIPv4(bad); got != nil {
			t.Errorf("parseIPv4(%q) 应返回 nil，实际 %v", bad, got)
		}
	}
}

// ---------- 周期循环 ----------

func TestLoopRespectsSwitchAndCancel(t *testing.T) {
	r, st, _, _ := newRunner(t, testCfg())
	r.tick = 10 * time.Millisecond

	// 配置用 atomic.Value 传递：测试 goroutine 改、Loop 读，必须无竞争
	var snap atomic.Value
	base := testCfg()
	base.DiscoverEnabled = false
	base.DiscoverSec = 1
	base.DiscoverCIDRs = []string{"10.0.0.0/8"} // 故意给一个超过上限的网段
	snap.Store(base)
	r.Cfg = func() model.SystemConfig { return snap.Load().(model.SystemConfig) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Loop(ctx); close(done) }()

	// 1) 开关关闭：不应扫描、不应落库
	time.Sleep(50 * time.Millisecond)
	if records, _ := st.ListPorts("", ""); len(records) != 0 {
		t.Fatalf("关闭状态下不应落库，实际 %d 条", len(records))
	}

	// 2) 开启但网段非法（/8 超过 8192 上限）：只应记错误，不落库、不 panic
	on := base
	on.DiscoverEnabled = true
	snap.Store(on)
	time.Sleep(50 * time.Millisecond)
	if records, _ := st.ListPorts("", ""); len(records) != 0 {
		t.Fatalf("非法网段不应产生记录，实际 %d 条", len(records))
	}

	// 3) 合法网段：走通一次完整扫描（本机 /32，端口基本都是 refusal，很快）
	ok := on
	ok.DiscoverCIDRs = []string{"127.0.0.1/32"}
	snap.Store(ok)
	time.Sleep(300 * time.Millisecond)
	for _, rec := range mustPorts(t, st) {
		if rec.Source != model.PortSourceProbe {
			t.Errorf("周期扫描落库的记录来源应为 probe，实际 %q", rec.Source)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("取消后 Loop 未退出（goroutine 泄漏）")
	}
}

// 周期为 0 时不应扫描（0 的语义是"仅手动触发"，不是"每 0 秒扫一次"）。
func TestLoopZeroIntervalIsManualOnly(t *testing.T) {
	r, st, _, _ := newRunner(t, testCfg())
	r.tick = 10 * time.Millisecond

	var snap atomic.Value
	cfg := testCfg()
	cfg.DiscoverEnabled = true
	cfg.DiscoverSec = 0
	cfg.DiscoverCIDRs = []string{"127.0.0.1/32"}
	snap.Store(cfg)
	r.Cfg = func() model.SystemConfig { return snap.Load().(model.SystemConfig) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Loop(ctx); close(done) }()
	time.Sleep(80 * time.Millisecond)
	if records, _ := st.ListPorts("", ""); len(records) != 0 {
		t.Errorf("周期为 0（仅手动）时不应自动扫描，实际落库 %d 条", len(records))
	}
	cancel()
	<-done
}

func mustPorts(t *testing.T, st *store.Store) []model.PortRecord {
	t.Helper()
	ps, err := st.ListPorts("", "")
	if err != nil {
		t.Fatalf("查询端口失败: %v", err)
	}
	return ps
}
