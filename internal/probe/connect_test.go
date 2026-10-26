package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- 端口档位 ----------

func TestPortPlanProfiles(t *testing.T) {
	cases := []struct {
		profile string
		wantMin int
		wantMax int
		wantLbl string
	}{
		{"quick", 80, 200, "内网高价值端口"},
		{"QUICK", 80, 200, "内网高价值端口"},    // 大小写不敏感
		{" top100 ", 80, 200, "内网高价值端口"}, // 别名 + 空白
		{"fast", 80, 200, "内网高价值端口"},
		{"standard", 1024, 2000, "1-1024 + 常见高位端口"},
		{"", 1024, 2000, "1-1024 + 常见高位端口"}, // 空串走默认档
		{"full", 65535, 65535, "1-65535 全端口"},
		{"ALL", 65535, 65535, "1-65535 全端口"},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			ports, label, err := PortPlan(c.profile)
			if err != nil {
				t.Fatalf("PortPlan(%q) 报错: %v", c.profile, err)
			}
			if label != c.wantLbl {
				t.Errorf("档位说明 = %q，期望 %q", label, c.wantLbl)
			}
			if len(ports) < c.wantMin || len(ports) > c.wantMax {
				t.Errorf("端口数 = %d，期望在 [%d,%d]", len(ports), c.wantMin, c.wantMax)
			}
			assertSortedUnique(t, c.profile, ports)
		})
	}
}

func TestPortPlanUnknown(t *testing.T) {
	ports, label, err := PortPlan("turbo")
	if err == nil {
		t.Fatal("未知档位应报错")
	}
	if ports != nil || label != "" {
		t.Errorf("报错时应返回空结果，实际 ports=%v label=%q", ports, label)
	}
	if want := `未知端口档位 "turbo"`; !strings.Contains(err.Error(), want) {
		t.Errorf("错误信息 = %q，应包含 %q", err.Error(), want)
	}
	// 错误信息要告诉用户有哪些合法值，否则前端只能靠猜
	if !strings.Contains(err.Error(), "quick|standard|full") {
		t.Errorf("错误信息应列出可选档位，实际 %q", err.Error())
	}
}

func TestPortPlanFullCoversEverything(t *testing.T) {
	ports, _, err := PortPlan(ProfileFull)
	if err != nil {
		t.Fatalf("full 档报错: %v", err)
	}
	if len(ports) != 65535 {
		t.Fatalf("full 档应有 65535 个端口，实际 %d", len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Errorf("full 档边界错误：首=%d 尾=%d", ports[0], ports[len(ports)-1])
	}
	for i, p := range ports {
		if p != i+1 {
			t.Fatalf("full 档第 %d 项 = %d，应为连续递增", i, p)
		}
	}
}

// 内网高价值端口是这次主动发现能力的核心资产，缺了任何一个都等于漏设备。
func TestQuickPortsHaveKeyInternalServices(t *testing.T) {
	ports, _, err := PortPlan(ProfileQuick)
	if err != nil {
		t.Fatalf("quick 档报错: %v", err)
	}
	set := map[int]bool{}
	for _, p := range ports {
		set[p] = true
	}
	// 远程管理 / 文件共享 / 数据库 / 常见 Web 管理口
	for _, must := range []int{22, 23, 135, 139, 445, 3389, 5985, 80, 443, 8080, 8443, 1433, 3306, 5432, 6379, 27017, 9200, 2181, 389} {
		if !set[must] {
			t.Errorf("quick 档缺少关键端口 %d", must)
		}
	}
}

func TestDedupSortedFiltersInvalid(t *testing.T) {
	in := []int{8080, -1, 0, 80, 8080, 70000, 80, 65535, 1}
	got := dedupSorted(in)
	want := []int{1, 80, 8080, 65535}
	if len(got) != len(want) {
		t.Fatalf("结果 = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("结果 = %v，期望 %v", got, want)
		}
	}
}

// Web/TLS 端口集合是"不对 65535 个端口都发 HTTP 请求"的闸门，必须包含最典型的几个。
func TestWebAndTLSPortSets(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 8443, 8000, 9000, 5000} {
		if !webPorts[p] {
			t.Errorf("webPorts 缺少 %d", p)
		}
	}
	for _, p := range []int{443, 465, 636, 993, 995, 8443, 5986, 10250} {
		if !tlsPorts[p] {
			t.Errorf("tlsPorts 缺少 %d", p)
		}
	}
	// 22/445 这类端口不该被当成 Web 发 HTTP 请求，否则会在目标日志里刷出一堆垃圾
	for _, p := range []int{22, 445, 3389} {
		if webPorts[p] {
			t.Errorf("webPorts 不应包含 %d", p)
		}
	}
}

// ---------- ScanOptions ----------

func TestScanOptionsNormalize(t *testing.T) {
	cases := []struct {
		name        string
		in          ScanOptions
		wantConc    int
		wantTimeout time.Duration
	}{
		{"零值取默认", ScanOptions{}, 256, 800 * time.Millisecond},
		{"负值取默认", ScanOptions{Concurrency: -10, Timeout: -time.Second}, 256, 800 * time.Millisecond},
		{"并发上限夹取", ScanOptions{Concurrency: 99999}, 2048, 800 * time.Millisecond},
		{"超时上限夹取", ScanOptions{Timeout: time.Minute}, 256, 10 * time.Second},
		{"正常值保留", ScanOptions{Concurrency: 64, Timeout: 2 * time.Second}, 64, 2 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in.normalize()
			if got.Concurrency != c.wantConc {
				t.Errorf("Concurrency = %d，期望 %d", got.Concurrency, c.wantConc)
			}
			if got.Timeout != c.wantTimeout {
				t.Errorf("Timeout = %v，期望 %v", got.Timeout, c.wantTimeout)
			}
		})
	}
}

func TestDefaultScanOptions(t *testing.T) {
	o := DefaultScanOptions()
	if o.Concurrency != 256 || o.Timeout != 800*time.Millisecond {
		t.Errorf("默认参数 = %+v，期望 256 / 800ms", o)
	}
	// 默认值再 normalize 一次应保持稳定（幂等）
	if got := o.normalize(); got != o {
		t.Errorf("normalize 不幂等：%+v → %+v", o, got)
	}
}

// ---------- ScanTCP ----------

// listenLocal 在 127.0.0.1 上起 n 个监听器，返回端口与清理函数。
func listenLocal(t *testing.T, n int) ([]int, func()) {
	t.Helper()
	var lns []net.Listener
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			t.Fatalf("本地监听失败: %v", err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports, func() {
		for _, l := range lns {
			_ = l.Close()
		}
	}
}

// closedPort 取一个"刚刚关掉、确定没人监听"的端口。
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// scanScanner 返回一个用真实时钟、不限速的扫描器（限速会拖慢测试）。
func scanScanner(t *testing.T) *Scanner {
	t.Helper()
	s, _ := newTestScanner()
	s.NowFunc = time.Now
	s.SetRate(0) // 测试里不需要限速
	return s
}

func TestScanTCPDetectsOpenPorts(t *testing.T) {
	openPorts, cleanup := listenLocal(t, 3)
	defer cleanup()
	shut := closedPort(t)

	s := scanScanner(t)
	targets := append(append([]int{}, openPorts...), shut)
	// 故意打乱顺序，验证结果被排序
	sort.Sort(sort.Reverse(sort.IntSlice(targets)))

	res, err := s.ScanTCP(context.Background(), "127.0.0.1", targets, ScanOptions{Concurrency: 16, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if res.IP != "127.0.0.1" {
		t.Errorf("IP = %q", res.IP)
	}
	if res.Scanned != len(targets) {
		t.Errorf("Scanned = %d，期望 %d", res.Scanned, len(targets))
	}

	got := map[int]bool{}
	for i, p := range res.Ports {
		got[p.Port] = true
		if i > 0 && res.Ports[i-1].Port >= p.Port {
			t.Errorf("结果未升序：%d 在 %d 之前", res.Ports[i-1].Port, p.Port)
		}
		if p.Latency < 0 {
			t.Errorf("端口 %d 延迟为负: %v", p.Port, p.Latency)
		}
	}
	for _, p := range openPorts {
		if !got[p] {
			t.Errorf("漏掉了开放端口 %d（实际结果 %v）", p, res.Ports)
		}
	}
	if got[shut] {
		t.Errorf("把已关闭的端口 %d 判成开放", shut)
	}
	if res.Elapsed == "" {
		t.Error("Elapsed 不应为空")
	}
}

func TestScanTCPEmptyPorts(t *testing.T) {
	s := scanScanner(t)
	res, err := s.ScanTCP(context.Background(), "127.0.0.1", nil, ScanOptions{})
	if err != nil {
		t.Fatalf("空端口列表不应报错: %v", err)
	}
	if res == nil {
		t.Fatal("结果不应为 nil")
	}
	if res.Scanned != 0 || len(res.Ports) != 0 {
		t.Errorf("空列表结果 = %+v，期望全空", res)
	}
	if res.Elapsed == "" {
		t.Error("空列表也应给出耗时（哪怕是 0s）")
	}
}

func TestScanTCPAllDialFail(t *testing.T) {
	s := scanScanner(t)
	var calls int64
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		atomic.AddInt64(&calls, 1)
		return nil, errors.New("connection refused")
	}
	ports := []int{21, 22, 23, 25, 80}
	res, err := s.ScanTCP(context.Background(), "10.0.0.1", ports, ScanOptions{Concurrency: 4})
	if err != nil {
		t.Fatalf("全部失败不应返回错误（端口关着是正常结果）: %v", err)
	}
	if len(res.Ports) != 0 {
		t.Errorf("全部失败时开放端口应为空，实际 %v", res.Ports)
	}
	if n := atomic.LoadInt64(&calls); n != int64(len(ports)) {
		t.Errorf("握手次数 = %d，期望 %d（每个端口一次）", n, len(ports))
	}
	if res.Scanned != len(ports) {
		t.Errorf("Scanned = %d，期望 %d", res.Scanned, len(ports))
	}
}

// 并发数大于端口数时不能起多余 worker（也不能死锁）。
func TestScanTCPMoreWorkersThanPorts(t *testing.T) {
	s := scanScanner(t)
	var calls int64
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		atomic.AddInt64(&calls, 1)
		return fakeConn{}, nil
	}
	res, err := s.ScanTCP(context.Background(), "10.0.0.1", []int{80, 443}, ScanOptions{Concurrency: 2048})
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if len(res.Ports) != 2 {
		t.Errorf("应识别 2 个开放端口，实际 %v", res.Ports)
	}
	if n := atomic.LoadInt64(&calls); n != 2 {
		t.Errorf("握手次数 = %d，期望 2（不能重复扫）", n)
	}
}

// fakeConn 一个只实现 net.Conn 的哑连接（Close 后不能 panic）。
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func TestScanTCPContextCancel(t *testing.T) {
	s := scanScanner(t)
	// 握手挂住直到上下文取消：模拟对不可达网段扫描时的真实表现
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ports := make([]int, 200)
	for i := range ports {
		ports[i] = 1000 + i
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)

	start := time.Now()
	res, err := s.ScanTCP(ctx, "10.255.255.1", ports, ScanOptions{Concurrency: 32, RatePPS: 100000, Timeout: 5 * time.Second})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("期望 context.Canceled，实际 %v", err)
	}
	if res == nil {
		t.Fatal("取消时也应返回结果对象")
	}
	if len(res.Ports) != 0 {
		t.Errorf("被取消的扫描不应有开放端口，实际 %v", res.Ports)
	}
	// 关键：取消必须真的中断，而不是等 200 个端口 × 5s 超时跑完
	if elapsed > 2*time.Second {
		t.Fatalf("取消后耗时 %v，说明没有及时中断", elapsed)
	}
}

// 超时设定必须真的生效：dial 阻塞到 deadline 也不能永久挂住。
func TestScanTCPTimeoutHonoured(t *testing.T) {
	s := scanScanner(t)
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		// 模拟 connect 在 timeout 时才返回
		select {
		case <-time.After(timeout):
			return nil, errors.New("i/o timeout")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	start := time.Now()
	res, err := s.ScanTCP(context.Background(), "10.255.255.1", []int{80, 81}, ScanOptions{Concurrency: 2, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("超时不应视为扫描错误: %v", err)
	}
	if len(res.Ports) != 0 {
		t.Errorf("超时的端口不应算开放: %v", res.Ports)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("耗时 %v，超时参数没生效", d)
	}
}

// ---------- 限速 ----------

func TestLimiterSpacesRequests(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	var slept []time.Duration

	l := newLimiter(100) // 100 pps → 每 10ms 一个许可
	l.nowFn = func() time.Time { return now }
	l.sleep = func(d time.Duration) {
		slept = append(slept, d)
		now = now.Add(d) // 睡完时钟前进
	}

	for i := 0; i < 4; i++ {
		if !l.wait(func() bool { return false }) {
			t.Fatalf("第 %d 次取许可被中断", i)
		}
	}
	issued, totalSlept := l.stats()
	if issued != 4 {
		t.Errorf("已发放许可 = %d，期望 4", issued)
	}
	// 第一次立即拿，后三次各等 10ms
	if len(slept) != 3 {
		t.Fatalf("实际等待 %d 次，期望 3 次（%v）", len(slept), slept)
	}
	for i, d := range slept {
		if d != 10*time.Millisecond {
			t.Errorf("第 %d 次等待 %v，期望 10ms", i, d)
		}
	}
	if totalSlept != 30*time.Millisecond {
		t.Errorf("累计等待 = %v，期望 30ms", totalSlept)
	}
}

// 时钟倒退 / 长时间空闲后不应累积巨额欠账（否则一次空闲后要"补睡"几十秒）。
func TestLimiterNoBacklogAfterIdle(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	var slept time.Duration
	l := newLimiter(10) // 100ms 间隔
	l.nowFn = func() time.Time { return now }
	l.sleep = func(d time.Duration) {
		slept += d
		now = now.Add(d)
	}

	l.wait(func() bool { return false })
	// 空闲一小时
	now = now.Add(time.Hour)
	l.wait(func() bool { return false })
	if slept != 0 {
		t.Errorf("空闲后应立即放行，实际等待 %v（出现补睡欠账）", slept)
	}
}

func TestLimiterCancelled(t *testing.T) {
	l := newLimiter(1000)
	if l.wait(func() bool { return true }) {
		t.Error("上下文已取消时 wait 应返回 false")
	}
}

func TestLimiterUnlimited(t *testing.T) {
	for _, pps := range []int{0, -5} {
		l := newLimiter(pps)
		done := make(chan struct{})
		go func() {
			for i := 0; i < 100; i++ {
				if !l.wait(func() bool { return false }) {
					t.Error("不限速时应始终放行")
					break
				}
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("pps=%d 时出现阻塞，说明不该限速", pps)
		}
		if issued, slept := l.stats(); issued != 0 || slept != 0 {
			t.Errorf("pps=%d 不限速时不应计数，实际 issued=%d slept=%v", pps, issued, slept)
		}
	}
}

// nil 限速器必须安全（大量代码路径可能拿到 nil）。
func TestLimiterNilSafe(t *testing.T) {
	var l *limiter
	if !l.wait(func() bool { return false }) {
		t.Error("nil limiter 应放行")
	}
	if issued, slept := l.stats(); issued != 0 || slept != 0 {
		t.Errorf("nil limiter stats = %d/%v", issued, slept)
	}
}

func TestLimiterConcurrentIssuedCount(t *testing.T) {
	l := newLimiter(1_000_000) // 间隔 1µs，几乎不睡
	l.nowFn = time.Now
	l.sleep = func(time.Duration) {} // 不真的睡，只验证计数与并发安全
	var wg atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				l.wait(func() bool { return false })
				wg.Add(1)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if n := wg.Load(); n != 400 {
		t.Errorf("放行次数 = %d，期望 400", n)
	}
	if issued, _ := l.stats(); issued != 400 {
		t.Errorf("issued = %d，期望 400（并发下不能漏计）", issued)
	}
}

// ---------- Scanner 限速接入 ----------

func TestLimiterForUsesDefaultRate(t *testing.T) {
	s, _ := newTestScanner() // 注意：不能走 scanScanner，它会把限速清零
	if s.defaultRate != DefaultRatePPS {
		t.Errorf("默认速率 = %d，期望 %d", s.defaultRate, DefaultRatePPS)
	}
	l := s.limiterFor(0)
	if l.rate != DefaultRatePPS {
		t.Errorf("limiter rate = %d，期望默认 %d", l.rate, DefaultRatePPS)
	}
	// 默认限速器应被复用（每次扫描新建一个等于没有全局限速）
	if again := s.limiterFor(0); again != l {
		t.Error("默认限速器未被复用，多主机扫描时会出现全局速率翻倍")
	}
	// 显式 pps 应独立成新限速器，不污染默认值
	custom := s.limiterFor(50)
	if custom == l {
		t.Error("显式 pps 不应复用默认限速器")
	}
	if custom.rate != 50 {
		t.Errorf("显式 pps rate = %d，期望 50", custom.rate)
	}
}

func TestSetRate(t *testing.T) {
	s := scanScanner(t)
	s.SetRate(1234)
	if got := s.limiterFor(0).rate; got != 1234 {
		t.Errorf("SetRate 后 rate = %d，期望 1234", got)
	}
	s.SetRate(0) // 不限速
	if got := s.limiterFor(0).rate; got != 0 {
		t.Errorf("SetRate(0) 后 rate = %d，期望 0", got)
	}
}

// 默认限速真的会约束扫描节奏：故意用极低 pps，观察耗时被拉长。
func TestScanTCPAppliesRateLimit(t *testing.T) {
	s, _ := newTestScanner()
	s.NowFunc = time.Now
	s.SetRate(0) // 清掉默认，下面显式传 RatePPS
	var calls int64
	s.dial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		atomic.AddInt64(&calls, 1)
		return nil, errors.New("refused")
	}
	ports := []int{1, 2, 3, 4, 5}
	start := time.Now()
	if _, err := s.ScanTCP(context.Background(), "10.0.0.1", ports, ScanOptions{Concurrency: 5, RatePPS: 50}); err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	// 50pps → 间隔 20ms → 5 个端口至少要 4 个间隔 = 80ms
	if d := time.Since(start); d < 60*time.Millisecond {
		t.Errorf("耗时 %v，限速 50pps 明显没生效（期望 ≥80ms 量级）", d)
	}
	if n := atomic.LoadInt64(&calls); n != 5 {
		t.Errorf("握手次数 = %d，期望 5", n)
	}
}

// ---------- 小工具 ----------

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", -1: "0", 1: "1", 9: "9", 10: "10", 80: "80", 443: "443", 8080: "8080", 65535: "65535"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q，期望 %q", in, got, want)
		}
	}
	// 与 strconv 对齐（it 是对它的手写替代，偏一位就等于扫错端口）
	for _, n := range []int{1, 7, 22, 3389, 12345, 65535} {
		if got, want := itoa(n), fmt.Sprint(n); got != want {
			t.Errorf("itoa(%d) = %q，strconv 为 %q", n, got, want)
		}
	}
}

func TestNowSinceClampsNegative(t *testing.T) {
	s := scanScanner(t)
	future := time.Now().Add(time.Hour)
	if d := s.nowSince(future); d != 0 {
		t.Errorf("时钟倒退应夹到 0，实际 %v", d)
	}
}

// ---------- 辅助 ----------

func assertSortedUnique(t *testing.T, name string, ports []int) {
	t.Helper()
	for i, p := range ports {
		if p <= 0 || p > 65535 {
			t.Fatalf("%s: 端口 %d 越界", name, p)
		}
		if i > 0 && ports[i-1] >= p {
			t.Fatalf("%s: 端口未严格升序（%d 后跟 %d）", name, ports[i-1], p)
		}
	}
}
