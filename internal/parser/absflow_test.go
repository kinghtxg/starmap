package parser

import (
	"testing"
	"time"
)

// 这一组用例锁的是字节数的语义：探针上报的是「从会话建立到现在的累计值」，
// 而且它每隔几秒会把同一条会话整条重发一遍。只要入口把它当增量处理，
// 流量就会随上报次数成倍膨胀——真实环境里是 13 倍起步、几百 GB 量级，
// 而界面上看不出任何异常，只是"流量很大"。

func absBase() time.Time { return time.Now().Add(-10 * time.Minute).UTC() }

func absFlow(up, down int64) *AbsFlow {
	first := absBase()
	return &AbsFlow{
		SrcIP:     "192.168.1.10",
		DstIP:     "203.0.113.5",
		SrcPort:   51000,
		DstPort:   443,
		Proto:     "tcp",
		MAC:       "aa:bb:cc:00:00:01",
		BytesUp:   up,
		BytesDown: down,
		Packets:   10,
		FirstSeen: first,
		LastSeen:  first.Add(5 * time.Minute),
	}
}

func absSession(t *testing.T, a *Aggregator) int64 {
	t.Helper()
	all := a.Sessions()
	if len(all) != 1 {
		t.Fatalf("应该只有一条会话，实际 %d", len(all))
	}
	return all[0].BytesUp + all[0].BytesDown
}

// TestIngestAbsIsIdempotent 同一份快照重复上报必须是幂等的。
// 这是整条链路的根约束：探针重发是常态（每 5 秒一次），不幂等就是无限放大。
func TestIngestAbsIsIdempotent(t *testing.T) {
	a := NewAggregator(3600, 64)
	f := absFlow(3000, 9000)
	for i := 0; i < 200; i++ {
		a.IngestAbs(f)
	}
	if got := absSession(t, a); got != 12000 {
		t.Fatalf("重复上报 200 次后应为 12000，实际 %d（放大 %.1f 倍）", got, float64(got)/12000)
	}
}

// TestIngestAbsCountsGrowth 累计值增长时只取增长后的绝对值，不是把每次的值加起来。
func TestIngestAbsCountsGrowth(t *testing.T) {
	a := NewAggregator(3600, 64)
	for _, v := range []int64{1000, 5000, 5000, 9000} {
		f := absFlow(v, 0)
		a.IngestAbs(f)
	}
	if got := absSession(t, a); got != 9000 {
		t.Fatalf("应为最终累计值 9000，实际 %d", got)
	}
}

// TestIngestAbsResetsOnTupleReuse 同一个客户端端口重新发起连接：
// 探针那边是新会话，累计值从 0 重新长。这里必须整体重置，
// 否则新连接的流量会被旧连接的峰值一直压住，永远算不进去。
func TestIngestAbsResetsOnTupleReuse(t *testing.T) {
	a := NewAggregator(3600, 64)
	f := absFlow(8000, 2000)
	a.IngestAbs(f)

	// 新连接：FirstSeen 更晚，累计值更小
	next := absFlow(600, 100)
	next.FirstSeen = f.FirstSeen.Add(30 * time.Minute)
	next.LastSeen = next.FirstSeen.Add(time.Minute)
	a.IngestAbs(next)

	if got := absSession(t, a); got != 700 {
		t.Fatalf("五元组复用后应重新从 0 计到 700，实际 %d", got)
	}
}

// TestIngestAbsNeverGoesBackwards 同一会话上报了更小的值（探针重启、或本地抓包
// 与探针同时在算同一条会话）时不能把已有数字打回去：一退回，下游的增量基准
// 就会跟着退，等于凭空重算一遍流量。
func TestIngestAbsNeverGoesBackwards(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.IngestAbs(absFlow(9000, 1000))

	smaller := absFlow(400, 100) // FirstSeen 相同 → 同一条会话，只是数字变小了
	a.IngestAbs(smaller)
	if got := absSession(t, a); got != 10000 {
		t.Fatalf("同一条会话的数字不应回退，应保持 10000，实际 %d", got)
	}
}

// TestIngestAbsKeepsIdentity 快照里的身份证据必须贯通到会话上：
// SNI/JA3/TTL 是探针最靠近设备时才能拿到的，丢了服务端只能靠端口猜。
func TestIngestAbsKeepsIdentity(t *testing.T) {
	a := NewAggregator(3600, 64)
	f := absFlow(1000, 2000)
	f.SNI = "example.com"
	f.JA3 = "d76a5a80b4bb0c75ac45782b0b53da91"
	f.JA4 = "t12d181100_5d04281c6031_8597d25ca141"
	f.StartTTL = 128
	f.UserAgent = "curl/8.0"
	f.HTTPServer = "nginx/1.18.0"
	f.XFF = []string{"10.8.8.8", "10.8.8.9"}
	f.XRealIP = "10.8.8.8"
	a.IngestAbs(f)

	all := a.Sessions()
	if len(all) != 1 {
		t.Fatalf("应有 1 条会话，实际 %d", len(all))
	}
	s := all[0]
	if s.SNI != "example.com" || s.JA3 != f.JA3 || s.JA4 != f.JA4 {
		t.Fatalf("TLS 指纹丢失: %+v", s)
	}
	if s.StartTTL != 128 {
		t.Fatalf("TTL 丢失: %d", s.StartTTL)
	}
	if s.UserAgent != "curl/8.0" || s.HTTPServer != "nginx/1.18.0" {
		t.Fatalf("明文 HTTP 身份头丢失: ua=%q server=%q", s.UserAgent, s.HTTPServer)
	}
	if s.RealClientIP != "10.8.8.8" || s.ProxyHops != 2 {
		t.Fatalf("XFF 还原丢失: real=%q hops=%d", s.RealClientIP, s.ProxyHops)
	}
}

// TestIngestAbsCapacityLimit 容量打满时丢新会话，而不是无限吃内存。
func TestIngestAbsCapacityLimit(t *testing.T) {
	a := NewAggregator(3600, 64)
	a.MaxSessions = 1
	a.IngestAbs(absFlow(1000, 1000))

	other := absFlow(1000, 1000)
	other.SrcPort = 51999
	a.IngestAbs(other)

	if got := len(a.Sessions()); got != 1 {
		t.Fatalf("容量上限 1 时应丢弃新会话，实际 %d 条", got)
	}
}
