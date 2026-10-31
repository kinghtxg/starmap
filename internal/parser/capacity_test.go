package parser

// 会话表打满后的成本回归测试（V1.5.2 新增）。
//
// 背景：旧实现在"表已满且新会话到来"时，每来一个就全表扫一遍找可回收会话。
// 实测 5 万表 23.15ms/会话，20 万上限线性外推约 92ms/会话——被动抓包在
// 这条路径上等于直接停摆。修复后同一场景应为微秒级。
//
// 断言用的是"绝对上界"而不是相对基线：这类回归的表现是数量级跳变
// （µs → ms），上界取 5ms 仍有上千倍余量，不会在慢机器上误报。

import (
	"fmt"
	"testing"
	"time"
)

// fillToCapacity 把会话表灌到上限，全部会话都"刚刚诞生"因此都不可回收。
// 这是最坏情况：淘汰扫描找不到任何可回收项。
func fillToCapacity(t *testing.T, a *Aggregator, n int, now time.Time) {
	t.Helper()
	a.SetLimits(n, 300, 21600)
	for i := 0; i < n; i++ {
		a.Ingest(&PacketInfo{
			Timestamp: now,
			SrcIP:     fmt.Sprintf("10.0.%d.%d", i/256%256, i%256),
			DstIP:     "8.8.8.8",
			SrcPort:   uint16(1024 + i%60000),
			DstPort:   443,
			Proto:     "tcp",
			Length:    1000,
		})
	}
	if got := a.Stats().Active; got != n {
		t.Fatalf("会话表未灌满：%d/%d", got, n)
	}
}

func TestIngestAtCapacityIsCheap(t *testing.T) {
	a := NewAggregator(3600, 64)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a.NowFunc = func() time.Time { return now }

	const capacity = 50000
	fillToCapacity(t, a, capacity, now)

	// 表已满，再来新会话。首次会触发一次门控扫描，后面的都走"直接丢弃"快路径。
	const extra = 200
	start := time.Now()
	for i := 0; i < extra; i++ {
		a.Ingest(&PacketInfo{
			Timestamp: now,
			SrcIP:     fmt.Sprintf("172.16.9.%d", i),
			DstIP:     "1.1.1.1",
			SrcPort:   uint16(30000 + i),
			DstPort:   80,
			Proto:     "tcp",
			Length:    800,
		})
	}
	elapsed := time.Since(start)
	perOp := elapsed / extra

	st := a.Stats()
	t.Logf("表满(%d)后处理 %d 个新会话：总计 %v，单会话 %v，Dropped=%d",
		capacity, extra, elapsed, perOp, st.Dropped)

	if st.Dropped != extra {
		t.Fatalf("表满且无可回收项时应全部丢弃，实际 Dropped=%d（期望 %d）", st.Dropped, extra)
	}
	if perOp > 5*time.Millisecond {
		t.Fatalf("【性能悬崖回归】表满后单会话耗时 %v，超过 5ms 上界。"+
			"修复前实测 23ms（5 万表）——说明淘汰又回到「每个新会话全表扫一遍」了。", perOp)
	}
}

// TestCapacityRecoversAfterIdle 门控不能让表永久卡在"满了但永不回收"。
// 时间推进到会话过期之后，下一次摄入必须能腾出空间并接纳新会话。
func TestCapacityRecoversAfterIdle(t *testing.T) {
	a := NewAggregator(3600, 64)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a.NowFunc = func() time.Time { return now }

	const capacity = 1000
	fillToCapacity(t, a, capacity, now)

	// 推进到所有会话都超过 idle(300s)，再次摄入新会话
	now = now.Add(10 * time.Minute)
	a.Ingest(&PacketInfo{
		Timestamp: now, SrcIP: "192.168.99.1", DstIP: "1.1.1.1",
		SrcPort: 40000, DstPort: 443, Proto: "tcp", Length: 900,
	})

	st := a.Stats()
	if st.Evicted == 0 {
		t.Fatalf("时间推进 10 分钟后仍未回收任何会话（Evicted=0），门控把回收彻底挡住了")
	}
	if st.Dropped != 0 {
		t.Fatalf("过期会话回收后应能接纳新会话，实际仍丢弃了 %d 条", st.Dropped)
	}
	if st.Active != 1 {
		t.Fatalf("回收后应只剩新会话 1 条，实际 %d", st.Active)
	}
}

// TestSweepGateDoesNotBlockExpiry 门控窗口内不扫描，但窗口一过必须扫。
func TestSweepGateDoesNotBlockExpiry(t *testing.T) {
	a := NewAggregator(3600, 64)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a.NowFunc = func() time.Time { return now }

	a.SetLimits(1000, 300, 21600)
	for i := 0; i < 10; i++ {
		a.Ingest(&PacketInfo{Timestamp: now, SrcIP: fmt.Sprintf("10.1.1.%d", i), DstIP: "1.1.1.1",
			SrcPort: uint16(1000 + i), DstPort: 443, Proto: "tcp", Length: 500})
	}

	// 刚扫过：1 秒后 Drain 不应再扫（返回的 Evicted 为空）
	now = now.Add(time.Second)
	if r := a.DrainNow(); len(r.Evicted) != 0 {
		t.Fatalf("门控窗口内不应重复扫描，实际回收 %d 条", len(r.Evicted))
	}

	// 推进到 idle 之后：必须扫到并回收
	now = now.Add(10 * time.Minute)
	r := a.DrainNow()
	if len(r.Evicted) != 10 {
		t.Fatalf("过了 idle 阈值应回收全部 10 条，实际 %d", len(r.Evicted))
	}
}
