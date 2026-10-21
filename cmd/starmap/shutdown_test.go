package main

import (
	"testing"
	"time"

	"starmap/internal/parser"
	"starmap/internal/store"
)

// 优雅退出时补落盘不能产生重复行 —— 历史实现每次退出都整表重插一遍，
// 退出几次 sessions 表就翻几倍。这个测试守住这条。
func TestPersistPendingSessionsNoDuplicates(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	agg := parser.NewAggregator(3600, 64)
	now := time.Now()

	// 第一条会话：模拟"周期同步已经写过库"
	agg.Ingest(&parser.PacketInfo{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80,
		Proto: "tcp", Length: 1000, Timestamp: now,
	})
	for _, e := range agg.DrainNow().Entries {
		ses := e.Session
		if !e.First {
			t.Fatal("首次抽取应为 First=true")
		}
		if _, err := st.SaveSession(&ses); err != nil {
			t.Fatal(err)
		}
	}

	// 第二条会话：只在退出前补写，之前没落过库
	agg.Ingest(&parser.PacketInfo{
		SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SrcPort: 40001, DstPort: 443,
		Proto: "tcp", Length: 1500, Timestamp: now,
	})

	if n := persistPendingSessions(agg, st); n != 1 {
		t.Fatalf("应只补写 1 条未落库会话，实际 %d", n)
	}

	// 再跑一次：没有新会话，不该再写
	if n := persistPendingSessions(agg, st); n != 0 {
		t.Fatalf("重复调用不应再写，实际 %d 条", n)
	}

	sessions, err := st.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions 表应有 2 行（无重复），实际 %d", len(sessions))
	}
}
