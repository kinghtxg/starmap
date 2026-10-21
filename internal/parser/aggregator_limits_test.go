package parser

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// mkPacket 构造一个最小可用报文（指定五元组与时间戳）。
func mkPacket(src, dst string, sport, dport uint16, ts time.Time) *PacketInfo {
	return &PacketInfo{
		SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport,
		Proto: "tcp", Length: 1000, Timestamp: ts,
	}
}

// fakeClock 可控时钟：让回收判定可以按需推进，测试不再依赖真实等待。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestDrainIsIncremental 增量语义：同一会话无新报文时，第二轮不该再被抽出。
func TestDrainIsIncremental(t *testing.T) {
	a := NewAggregator(3600, 64)
	now := time.Now()
	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, now))

	r1 := a.Drain(now)
	if len(r1.Entries) != 1 {
		t.Fatalf("首轮应抽出 1 条，实际 %d", len(r1.Entries))
	}
	if !r1.Entries[0].First {
		t.Fatal("首轮应为 First=true")
	}

	r2 := a.Drain(now)
	if len(r2.Entries) != 0 {
		t.Fatalf("无新报文时第二轮应为 0 条，实际 %d", len(r2.Entries))
	}

	// 再来一个包 → 只抽出这一条，且 First=false
	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, now.Add(time.Second)))
	r3 := a.Drain(now.Add(time.Second))
	if len(r3.Entries) != 1 {
		t.Fatalf("有新报文应抽出 1 条，实际 %d", len(r3.Entries))
	}
	if r3.Entries[0].First {
		t.Fatal("同一会话第二次抽出应为 First=false（避免重复落库）")
	}
	if r3.Entries[0].Session.Packets != 2 {
		t.Fatalf("包数应为 2，实际 %d", r3.Entries[0].Session.Packets)
	}
}

// TestDrainEvictsIdleSession 静默超阈值的会话被回收。
func TestDrainEvictsIdleSession(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(1000, 60, 3600)
	clk := newFakeClock(time.Now())
	a.NowFunc = clk.Now

	t0 := clk.Now()
	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, t0))
	a.DrainNow()

	// 静默 61 秒（> idle 60s）→ 应被回收
	clk.Advance(61 * time.Second)
	r := a.DrainNow()
	if len(r.Evicted) != 1 {
		t.Fatalf("应回收 1 条静默会话，实际 %d", len(r.Evicted))
	}
	if r.Active != 0 {
		t.Fatalf("回收后活动会话应为 0，实际 %d", r.Active)
	}
}

// TestDrainEvictsClosedSessionAfterGrace 已 FIN 的会话在收尾窗口后被回收。
func TestDrainEvictsClosedSessionAfterGrace(t *testing.T) {
	a := NewAggregator(3600, 64)
	clk := newFakeClock(time.Now())
	a.NowFunc = clk.Now

	t0 := clk.Now()
	p := mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, t0)
	p.TCPFlags = 0x01 // FIN
	a.Ingest(p)
	a.DrainNow()

	clk.Advance(closedGraceSeconds*time.Second + time.Second)
	r := a.DrainNow()
	if len(r.Evicted) != 1 {
		t.Fatalf("已关闭会话应在宽限期后被回收，实际回收 %d", len(r.Evicted))
	}
}

// TestDrainKeepsActiveLongConn 仍在发包的长连接不能被误回收。
func TestDrainKeepsActiveLongConn(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(1000, 60, 100)
	clk := newFakeClock(time.Now())
	a.NowFunc = clk.Now

	// 持续发包 200 秒：超过 maxAge(100s)，但一直有流量 → 仍应保留
	for i := 0; i <= 200; i += 20 {
		a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, clk.Now()))
		a.DrainNow()
		clk.Advance(20 * time.Second)
	}
	if st := a.Stats(); st.Active != 1 {
		t.Fatalf("持续活跃的会话不应被回收，实际 Active=%d", st.Active)
	}
}

// TestMaxAgeEvictsStaleLongConn 长期不关闭但已无流量的连接，靠 maxAge 兜底回收。
func TestMaxAgeEvictsStaleLongConn(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(1000, 100000, 60) // idle 极大，只让 maxAge 生效
	clk := newFakeClock(time.Now())
	a.NowFunc = clk.Now

	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, clk.Now()))
	a.DrainNow()

	clk.Advance(61 * time.Second)
	r := a.DrainNow()
	if len(r.Evicted) != 1 {
		t.Fatalf("超 maxAge 的会话应被回收，实际 %d", len(r.Evicted))
	}
}

// TestHistoricalPacketNotEvictedImmediately 回归测试：
// 导入历史 PCAP（报文时间远早于当前墙钟）时，不得在第一轮就被当成超时清空。
func TestHistoricalPacketNotEvictedImmediately(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(1000, 300, 21600)

	old := time.Now().Add(-72 * time.Hour) // 三天前的抓包
	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, old))

	r := a.Drain(time.Now())
	if len(r.Entries) != 1 {
		t.Fatalf("历史报文应正常产出 1 条会话，实际 %d（被按报文时间误回收）", len(r.Entries))
	}
	if len(r.Evicted) != 0 {
		t.Fatalf("历史报文不应立即被回收，实际回收 %d", len(r.Evicted))
	}
}

// TestMaxSessionsDropsNew 达到上限且无可回收会话时，丢弃新会话并计数。
func TestMaxSessionsDropsNew(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(10, 300, 21600)
	now := time.Now()

	for i := 0; i < 30; i++ {
		a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", uint16(40000+i), 80, now))
	}
	st := a.Stats()
	if st.Active != 10 {
		t.Fatalf("会话数应被限制在 10，实际 %d", st.Active)
	}
	if st.Dropped != 20 {
		t.Fatalf("应丢弃 20 条新会话，实际 %d", st.Dropped)
	}
}

// TestMaxSessionsEvictsBeforeDropping 达上限时先回收过期会话，能回收就不该丢弃。
func TestMaxSessionsEvictsBeforeDropping(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(5, 10, 3600)
	clk := newFakeClock(time.Now())
	a.NowFunc = clk.Now

	for i := 0; i < 5; i++ {
		a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", uint16(40000+i), 80, clk.Now()))
	}
	if st := a.Stats(); st.Active != 5 {
		t.Fatalf("应建立 5 条会话，实际 %d", st.Active)
	}

	// 静默 30 秒后（> idle 10s）再来新会话：应先回收旧的 5 条，不应丢弃
	clk.Advance(30 * time.Second)
	a.Ingest(mkPacket("10.0.0.9", "10.0.0.8", 40001, 80, clk.Now()))
	st := a.Stats()
	if st.Dropped != 0 {
		t.Fatalf("可回收时不应丢弃新会话，实际 Dropped=%d", st.Dropped)
	}
	if st.Evicted != 5 {
		t.Fatalf("应先回收 5 条过期会话，实际 Evicted=%d", st.Evicted)
	}
}

// TestPacketSampleWindowCapped 心跳采样数组必须有上限，否则长连接会无界吃内存。
func TestPacketSampleWindowCapped(t *testing.T) {
	a := NewAggregator(3600, 64)
	t0 := time.Now()

	// 1000 个小包，间隔 100ms（构成心跳特征）
	for i := 0; i < 1000; i++ {
		p := mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, t0.Add(time.Duration(i)*100*time.Millisecond))
		p.Length = 20 // 小包
		a.Ingest(p)
	}

	a.mu.Lock()
	var st *sessionState
	for _, v := range a.sessions {
		st = v
	}
	gaps, lens := len(st.packetGaps), len(st.packetLens)
	a.mu.Unlock()

	if gaps > maxPacketSamples || lens > maxPacketSamples {
		t.Fatalf("采样窗口未封顶：gaps=%d lens=%d 上限=%d", gaps, lens, maxPacketSamples)
	}
	// 仍应能判定出心跳（最近窗口仍是 100ms 周期）
	r := a.Drain(t0.Add(200 * time.Second))
	if len(r.Entries) != 1 {
		t.Fatalf("应抽出 1 条会话，实际 %d", len(r.Entries))
	}
	if got := r.Entries[0].Session.HeartbeatIntervalMs; got != 100 {
		t.Fatalf("心跳间隔应为 100ms，实际 %d", got)
	}
}

// TestConcurrentIngestAndDrain 并发摄入 + 并发抽取：验证无 panic / 无死锁 / 计数守恒。
// 本机没装 gcc 跑不了 -race，这个测试在 CI（Linux）上会以 -race 再跑一遍。
func TestConcurrentIngestAndDrain(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(100000, 300, 21600)
	now := time.Now()

	const workers = 8
	const perWorker = 500
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				src := fmt.Sprintf("10.1.%d.%d", w, i%200)
				a.Ingest(mkPacket(src, "10.9.9.9", uint16(40000+i), 80, now))
			}
		}(w)
	}
	// 同时跑两个抽取者，制造读写交错
	var drained int
	var dmu sync.Mutex
	for d := 0; d < 2; d++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r := a.Drain(now)
				dmu.Lock()
				drained += len(r.Entries)
				dmu.Unlock()
			}
		}()
	}
	wg.Wait()

	// 收尾再抽一次，把所有残留的 dirty 抽出来
	r := a.Drain(now)
	// 每个 (src,dport) 组合都是独立五元组：workers × perWorker 条
	want := workers * perWorker
	if r.Active != want {
		t.Fatalf("会话数应为 %d，实际 %d", want, r.Active)
	}
	if r.Dropped != 0 {
		t.Fatalf("远未达上限，不应丢弃，实际 %d", r.Dropped)
	}
	if drained+len(r.Entries) != want {
		t.Fatalf("抽出总数应为 %d（无重复无遗漏）：drained=%d + last=%d",
			want, drained, len(r.Entries))
	}
}

// TestStatsReflectsState Stats 指标应与会话表真实状态一致。
func TestStatsReflectsState(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.SetLimits(42, 60, 3600)
	now := time.Now()

	a.Ingest(mkPacket("10.0.0.1", "10.0.0.2", 50000, 80, now))
	st := a.Stats()
	if st.Active != 1 || st.MaxSessions != 42 {
		t.Fatalf("Stats 不符：%+v", st)
	}
}
