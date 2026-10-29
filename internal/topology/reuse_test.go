package topology

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// 五元组复用：同一个客户端端口关掉连接后又重新发起连接，是很常见的
// （NAT、长跑客户端、端口随机池小的系统都会碰到）。聚合器那边是全新会话，
// 累计值从 0 重新长。如果按"比上次小就当 0 增量"处理，这条新连接的全部流量
// 会被旧连接的峰值压住，直到它超过旧值——表现就是"某台机器突然没流量了"，
// 而它明明还在激烈通信。
func TestReusedFiveTupleCountsNewConnection(t *testing.T) {
	e := New(testCfg())
	t0 := time.Date(2025, 5, 1, 10, 0, 0, 0, time.UTC)

	first := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "192.168.7.7", DstIP: "203.0.113.20", SrcPort: 51000, DstPort: 443, Proto: "tcp"},
		MAC:       "aa:bb:cc:00:00:07",
		FirstSeen: t0, LastSeen: t0.Add(time.Minute),
		BytesUp: 8000, BytesDown: 2000, Packets: 40,
	}
	e.Ingest(first)

	// 同一条四元组上的新连接：FirstSeen 前移，累计值从 0 重新长
	second := &model.Session{
		FiveTuple: first.FiveTuple,
		MAC:       first.MAC,
		FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour + time.Minute),
		BytesUp: 600, BytesDown: 100, Packets: 6,
	}
	e.Ingest(second)

	if got := totalEdgeBytes(t, e); got != 10700 {
		t.Fatalf("旧连接 10000 + 新连接 700 应为 10700，实际 %d（新连接的流量被压住了）", got)
	}
}

// 反过来的护栏：FirstSeen 每次上报都往后走、累计值却一直涨，这是很多采集
// 路径的正常行为（每次上报都拿"现在"当 FirstSeen）。这种情况绝不能被判成
// 新连接——一判就是每次上报都整笔再加一次，比原来少算更糟。
func TestAdvancingFirstSeenKeepsAccumulating(t *testing.T) {
	e := New(testCfg())
	t0 := time.Date(2025, 5, 1, 10, 0, 0, 0, time.UTC)

	for i, up := range []int64{1000, 4000, 9000} {
		s := &model.Session{
			FiveTuple: model.FiveTuple{SrcIP: "192.168.7.8", DstIP: "203.0.113.21", SrcPort: 51001, DstPort: 443, Proto: "tcp"},
			MAC:       "aa:bb:cc:00:00:08",
			FirstSeen: t0.Add(time.Duration(i) * time.Minute), // 每次都往后走
			LastSeen:  t0.Add(time.Duration(i+1) * time.Minute),
			BytesUp:   up, BytesDown: 0, Packets: 10,
		}
		e.Ingest(s)
	}
	if got := totalEdgeBytes(t, e); got != 9000 {
		t.Fatalf("累计到 9000 应仍为 9000，实际 %d（被误判成新连接后整笔重加）", got)
	}
}
