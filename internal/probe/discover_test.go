package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withPortPlan 临时替换端口档位解析（测试只能用随机高位端口，无法真扫 1-1024）。
func withPortPlan(t *testing.T, fn func(string) ([]int, string, error)) {
	t.Helper()
	orig := portPlanFor
	portPlanFor = fn
	t.Cleanup(func() { portPlanFor = orig })
}

// ---------- 端口挑选 ----------

func TestSelectFingerprintPorts(t *testing.T) {
	ports := []OpenPort{
		{Port: 445}, {Port: 8080}, {Port: 22}, {Port: 443},
		{Port: 3389}, {Port: 21}, {Port: 8443}, {Port: 9200},
	}
	got := selectFingerprintPorts(ports, 4)
	// 443/8443 是 TLS（证书最有价值），8080/9200 是 Web；445/3389/22/21 靠后
	want := []int{443, 8080, 8443, 9200}
	if len(got) != len(want) {
		t.Fatalf("挑选结果 = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("挑选结果 = %v，期望 %v", got, want)
		}
	}
}

func TestSelectFingerprintPortsCap(t *testing.T) {
	ports := []OpenPort{{Port: 443}, {Port: 8080}, {Port: 22}, {Port: 3389}}
	if got := selectFingerprintPorts(ports, 1); len(got) != 1 || got[0] != 443 {
		t.Errorf("上限 1 时应只留最高价值的 443，实际 %v", got)
	}
	// 上限大于端口数时全给
	if got := selectFingerprintPorts(ports, 100); len(got) != 4 {
		t.Errorf("上限较大时应全给，实际 %v", got)
	}
	// 空输入
	if got := selectFingerprintPorts(nil, 8); len(got) != 0 {
		t.Errorf("空输入应返回空，实际 %v", got)
	}
	// 结果必须升序（入库与界面展示依赖这个顺序）
	got := selectFingerprintPorts(ports, 0)
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("结果未升序: %v", got)
		}
	}
}

// ---------- 选项 ----------

func TestDiscoverOptionsNormalize(t *testing.T) {
	o := DefaultDiscoverOptions().normalize()
	if o.Profile != ProfileStandard || o.HostConcurrency != 4 || o.MaxFingerprintPorts != 32 {
		t.Errorf("默认值 = %+v", o)
	}
	if o.Scan.Concurrency != 256 || o.Fingerprint.Timeout != 3*time.Second {
		t.Errorf("子选项未归一化: %+v", o)
	}

	bad := DiscoverOptions{HostConcurrency: -3, MaxFingerprintPorts: 9999}.normalize()
	if bad.HostConcurrency != 4 {
		t.Errorf("非法主机并发应回落 4，实际 %d", bad.HostConcurrency)
	}
	if bad.MaxFingerprintPorts != 256 {
		t.Errorf("指纹端口上限应夹到 256，实际 %d", bad.MaxFingerprintPorts)
	}
	if big := (DiscoverOptions{HostConcurrency: 1000}).normalize(); big.HostConcurrency != 64 {
		t.Errorf("主机并发应夹到 64，实际 %d", big.HostConcurrency)
	}
}

// ---------- 参数校验 ----------

func TestDiscoverNoTargets(t *testing.T) {
	s := newFPScanner(t)
	if _, err := s.Discover(context.Background(), nil, DefaultDiscoverOptions()); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("空目标应返回 ErrNoTargets，实际 %v", err)
	}
}

func TestDiscoverInvalidProfile(t *testing.T) {
	s := newFPScanner(t)
	opt := DefaultDiscoverOptions()
	opt.Profile = "turbo"
	if _, err := s.Discover(context.Background(), []string{"10.0.0.1"}, opt); err == nil {
		t.Fatal("非法档位应报错")
	}
}

func TestDiscoverOutsideWindow(t *testing.T) {
	s, _ := newTestScanner()
	// 固定时钟：03:00，窗口 09:00-18:00 之外
	s.NowFunc = func() time.Time { return time.Date(2025, 1, 1, 3, 0, 0, 0, time.Local) }
	s.SetRate(0)

	w, err := ParseWindow("09:00-18:00")
	if err != nil {
		t.Fatalf("解析窗口失败: %v", err)
	}
	opt := DefaultDiscoverOptions()
	opt.Window = &w
	if _, err := s.Discover(context.Background(), []string{"10.0.0.1"}, opt); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("窗口外应拒绝执行，实际 %v", err)
	}
}

func TestDiscoverInvalidCIDR(t *testing.T) {
	s := newFPScanner(t)
	if _, err := s.DiscoverCIDR(context.Background(), "not-a-cidr", DefaultDiscoverOptions()); err == nil {
		t.Fatal("非法网段应报错")
	}
	// /8 有 1600 万地址，必须拒绝（否则一次误操作就能把内网打穿）
	if _, err := s.DiscoverCIDR(context.Background(), "10.0.0.0/8", DefaultDiscoverOptions()); err == nil {
		t.Fatal("过大网段应被拒绝")
	}
}

// ---------- 端到端（真实本地服务）----------

func TestDiscoverFindsAndFingerprints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte(`<html><title>内网门户</title></html>`))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)

	withPortPlan(t, func(string) ([]int, string, error) {
		return []int{port}, "测试端口集", nil
	})

	s := newFPScanner(t)
	var progress []Progress
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 500 * time.Millisecond
	opt.Fingerprint = objNoFavicon()
	opt.OnProgress = func(p Progress) { progress = append(progress, p) }

	res, err := s.Discover(context.Background(), []string{"127.0.0.1"}, opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if res.Total != 1 || res.Alive != 1 || res.OpenPorts != 1 {
		t.Errorf("汇总 = total %d / alive %d / ports %d，期望 1/1/1", res.Total, res.Alive, res.OpenPorts)
	}
	h := res.Hosts[0]
	if !h.Alive || len(h.Ports) != 1 || h.Ports[0].Port != port {
		t.Fatalf("主机结果异常: %+v", h)
	}
	if len(h.Fingerprints) != 1 {
		t.Fatalf("应有 1 条指纹，实际 %+v", h.Fingerprints)
	}
	fp := h.Fingerprints[0]
	if fp.Product != "nginx" || fp.Version != "1.24.0" || fp.Title != "内网门户" {
		t.Errorf("指纹内容异常: %+v", fp)
	}
	if res.Fingerprints != 1 {
		t.Errorf("指纹计数 = %d，期望 1", res.Fingerprints)
	}
	if h.Elapsed == "" || res.Duration == "" {
		t.Error("耗时应被记录")
	}
	if len(progress) != 1 || progress[0].Done != 1 || progress[0].Total != 1 || progress[0].IP != "127.0.0.1" {
		t.Errorf("进度回调异常: %+v", progress)
	}
	if progress[0].Fingerprints != 1 {
		t.Errorf("进度里的指纹数 = %d", progress[0].Fingerprints)
	}
}

func TestDiscoverMixedAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>alive</title></html>"))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)

	withPortPlan(t, func(string) ([]int, string, error) { return []int{port}, "测试", nil })

	s := newFPScanner(t)
	// 除 127.0.0.1 外一律当作不可达
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		if strings.HasPrefix(addr, "127.0.0.1:") {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
		}
		return nil, errors.New("no route to host")
	}

	hosts := []string{"10.1.1.1", "127.0.0.1", "10.1.1.2", "10.1.1.3"}
	var done int
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 300 * time.Millisecond
	opt.SkipFingerprint = true
	opt.OnProgress = func(p Progress) {
		if p.Done == 1 && done != 0 {
			t.Errorf("进度不应重复上报 Done=1")
		}
		done = p.Done
	}

	res, err := s.Discover(context.Background(), hosts, opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if res.Total != 4 || res.Alive != 1 {
		t.Errorf("汇总 = total %d / alive %d，期望 4/1", res.Total, res.Alive)
	}
	if len(res.Hosts) != 4 {
		t.Fatalf("应保留每个主机的记录，实际 %d", len(res.Hosts))
	}
	// 结果顺序必须与输入顺序一致（界面按网段顺序展示，乱序会被当成漏扫）
	for i, ip := range hosts {
		if res.Hosts[i].IP != ip {
			t.Errorf("第 %d 个主机 = %q，期望 %q", i, res.Hosts[i].IP, ip)
		}
	}
	if !res.Hosts[1].Alive {
		t.Error("127.0.0.1 应为存活")
	}
	// 跳过指纹时不应有任何指纹
	for _, h := range res.Hosts {
		if len(h.Fingerprints) != 0 {
			t.Errorf("%s 不该有指纹: %+v", h.IP, h.Fingerprints)
		}
	}
	if done != 4 {
		t.Errorf("最终进度 Done = %d，期望 4", done)
	}
}

func TestDiscoverKnownHostDowngrade(t *testing.T) {
	var asked []string
	withPortPlan(t, func(profile string) ([]int, string, error) {
		asked = append(asked, profile)
		if profile == ProfileQuick {
			return []int{1}, "内网高价值端口", nil
		}
		return []int{2}, "1-1024 + 常见高位端口", nil
	})

	s := newFPScanner(t)
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("refused")
	}

	opt := DefaultDiscoverOptions()
	opt.SkipFingerprint = true
	opt.Known = func(ip string) bool { return ip == "10.0.0.5" }

	res, err := s.Discover(context.Background(), []string{"10.0.0.5", "10.0.0.6"}, opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if !strings.Contains(res.Hosts[0].Profile, "降频") {
		t.Errorf("已知主机应降频，实际档位 %q", res.Hosts[0].Profile)
	}
	if strings.Contains(res.Hosts[1].Profile, "降频") {
		t.Errorf("未知主机不应降频，实际档位 %q", res.Hosts[1].Profile)
	}
	// 降频档位只能在"有已知主机判定"时才计算，避免白算
	foundQuick := false
	for _, p := range asked {
		if p == ProfileQuick {
			foundQuick = true
		}
	}
	if !foundQuick {
		t.Errorf("应请求过 quick 档端口集，实际 %v", asked)
	}
}

func TestDiscoverFingerprintCap(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>srv1</title></html>"))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>srv2</title></html>"))
	}))
	defer srv2.Close()

	p1, p2 := serverPort(t, srv1.URL), serverPort(t, srv2.URL)
	withPortPlan(t, func(string) ([]int, string, error) { return []int{p1, p2}, "测试", nil })

	s := newFPScanner(t)
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 500 * time.Millisecond
	opt.Fingerprint = objNoFavicon()
	opt.MaxFingerprintPorts = 1

	res, err := s.Discover(context.Background(), []string{"127.0.0.1"}, opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	h := res.Hosts[0]
	if len(h.Ports) != 2 {
		t.Fatalf("应扫到 2 个开放端口，实际 %+v", h.Ports)
	}
	// 两个都是未知高位端口 → 同分，按端口升序取第一个
	if len(h.Fingerprints) != 1 {
		t.Fatalf("指纹上限 1 时应只有 1 条，实际 %+v", h.Fingerprints)
	}
	want := p1
	if p2 < p1 {
		want = p2
	}
	if h.Fingerprints[0].Port != want {
		t.Errorf("指纹端口 = %d，期望 %d（同分时取小端口）", h.Fingerprints[0].Port, want)
	}
}

func TestDiscoverContextCancel(t *testing.T) {
	s := newFPScanner(t)
	withPortPlan(t, func(string) ([]int, string, error) { return []int{80, 443}, "测试", nil })
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	hosts := []string{"10.9.9.1", "10.9.9.2", "10.9.9.3"}
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 5 * time.Second

	start := time.Now()
	res, err := s.Discover(ctx, hosts, opt)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 context.Canceled，实际 %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("取消后耗时 %v，说明没有及时中断", d)
	}
	// 取消属于"没扫"，不是"主机不存在"：不能把它们记成 Error 之外的假阴性
	if res == nil {
		t.Fatal("取消时也应返回部分结果")
	}
	if res.Alive != 0 {
		t.Errorf("取消后不该有存活主机，实际 %d", res.Alive)
	}
}

func TestDiscoverCIDRSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>cidr</title></html>"))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)

	withPortPlan(t, func(string) ([]int, string, error) { return []int{port}, "测试", nil })

	s := newFPScanner(t)
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 500 * time.Millisecond
	opt.SkipFingerprint = true

	res, err := s.DiscoverCIDR(context.Background(), "127.0.0.1/32", opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if res.Total != 1 || res.Alive != 1 {
		t.Errorf("/32 网段结果 = total %d / alive %d，期望 1/1", res.Total, res.Alive)
	}
	if res.Hosts[0].IP != "127.0.0.1" {
		t.Errorf("主机 = %q", res.Hosts[0].IP)
	}
}

// ---------- 调度：时间窗口 ----------

func TestParseWindow(t *testing.T) {
	ok := []struct {
		in       string
		wantSpec string
	}{
		{"", "全天"},
		{"   ", "全天"},
		{"22:00-06:00", "22:00-06:00"},
		{"9:00-18:30", "09:00-18:30"},
		{"00:00-00:00", "00:00-00:00"},
	}
	for _, c := range ok {
		w, err := ParseWindow(c.in)
		if err != nil {
			t.Errorf("ParseWindow(%q) 报错: %v", c.in, err)
			continue
		}
		if w.String() != c.wantSpec {
			t.Errorf("ParseWindow(%q).String() = %q，期望 %q", c.in, w.String(), c.wantSpec)
		}
	}
	bad := []string{"22-06", "25:00-06:00", "22:00-24:00", "aa:00-06:00", "22:xx-06:00", "22:00-06:99"}
	for _, c := range bad {
		if _, err := ParseWindow(c); err == nil {
			t.Errorf("%q 应解析失败", c)
		}
	}
}

func TestWindowContains(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2025, 6, 1, h, m, 0, 0, time.Local) }

	night, _ := ParseWindow("22:00-06:00")
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(23, 0), true},
		{at(22, 0), true}, // 起始含
		{at(3, 30), true}, // 跨夜
		{at(6, 0), false}, // 结束不含
		{at(12, 0), false},
		{at(21, 59), false},
	}
	for _, c := range cases {
		if got := night.Contains(c.t); got != c.want {
			t.Errorf("跨夜窗口 %v 判定 = %v，期望 %v", c.t, got, c.want)
		}
	}

	day, _ := ParseWindow("09:00-18:00")
	if !day.Contains(at(9, 0)) || !day.Contains(at(17, 59)) {
		t.Error("同日窗口内应允许")
	}
	if day.Contains(at(18, 0)) || day.Contains(at(8, 59)) {
		t.Error("同日窗口边界应拒绝")
	}

	all, _ := ParseWindow("")
	if !all.Contains(at(0, 0)) || !all.Contains(at(23, 59)) {
		t.Error("空窗口应全天允许")
	}
	same, _ := ParseWindow("00:00-00:00")
	if !same.Contains(at(3, 0)) {
		t.Error("起止相同应视为全天")
	}
}

// ---------- 调度：失败退避 ----------

func TestBackoffExponential(t *testing.T) {
	b := NewBackoff(time.Minute, 10*time.Minute)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		got := b.Fail("10.0.0.1", now)
		if got != w {
			t.Errorf("第 %d 次失败退避 = %v，期望 %v", i+1, got, w)
		}
	}
	if b.Fails("10.0.0.1") != len(want) {
		t.Errorf("失败次数 = %d，期望 %d", b.Fails("10.0.0.1"), len(want))
	}
}

func TestBackoffDueAndReset(t *testing.T) {
	b := NewBackoff(time.Minute, time.Hour)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	if !b.Due("10.0.0.1", now) {
		t.Error("无退避记录时应允许扫描")
	}
	d := b.Fail("10.0.0.1", now)
	if b.Due("10.0.0.1", now.Add(d/2)) {
		t.Error("退避期内不应允许扫描")
	}
	if !b.Due("10.0.0.1", now.Add(d)) {
		t.Error("退避到期后应允许扫描")
	}
	if nr := b.NextRetry("10.0.0.1"); !nr.Equal(now.Add(d)) {
		t.Errorf("下次重试时刻 = %v，期望 %v", nr, now.Add(d))
	}

	b.Succeed("10.0.0.1")
	if b.Fails("10.0.0.1") != 0 {
		t.Error("成功后应清零失败次数")
	}
	if !b.NextRetry("10.0.0.1").IsZero() {
		t.Error("成功后不应再有重试时刻")
	}
	// 成功后再次失败应从最短退避重新开始
	if got := b.Fail("10.0.0.1", now); got != time.Minute {
		t.Errorf("重置后退避 = %v，期望 1 分钟", got)
	}
}

func TestBackoffDefaultsAndIsolation(t *testing.T) {
	b := NewBackoff(0, 0)
	if got := b.Fail("a", time.Now()); got != time.Minute {
		t.Errorf("默认初始退避 = %v，期望 1 分钟", got)
	}
	// max < base 时应把 max 抬到 base，避免退避时长为 0
	b2 := NewBackoff(time.Hour, time.Minute)
	if got := b2.Fail("a", time.Now()); got != time.Hour {
		t.Errorf("max<base 时退避 = %v，期望 1 小时", got)
	}
	// 一台机器的退避不能影响另一台（否则一台断电会拖住全网）
	b.Fail("x", time.Now())
	if !b.Due("y", time.Now()) {
		t.Error("不同主机的退避状态必须互相独立")
	}
}
