package topology

import (
	"path/filepath"
	"testing"
	"time"

	"starmap/internal/store"
)

// 重启不能让流量翻倍。
//
// 边的字节是"探针两次上报之间的增量"累加出来的，增量要减掉上一次看到的值。
// 这个"上一次"原本只存在内存里 —— 进程重启后它没了，仍在持续的会话会被当成
// 新会话整笔再加一次。真实环境里重启几轮之后，1.6GB 变成 750GB：
// 界面上只是一个更大的数字，没有任何地方报错，也不会有人发现。
//
// 修复方式是把最近活跃会话的累计值落到 session_offsets（运行态状态表），
// 启动时接回来（Engine.sessionMaxAge 作为窗口）。不能拿 sessions 历史表当基准：
// 那张表只在会话首次出现时插一行，字节数停在首见那一刻，基准偏小还是会翻倍。
func TestRestartDoesNotDoubleCountBytes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "restart.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := testCfg()
	s := sessionTo("10.1.1.10", "10.1.1.20", 50001, 445, "tcp", base)
	// 用真实时间：恢复增量基准只取最近 sessionMaxAge 内的会话，
	// 固定基准时间（2025-01-01）会被正确地过滤掉——那正是线上不会发生的情况。
	now := time.Now().UTC()
	s.FirstSeen, s.LastSeen = now.Add(-time.Minute), now
	s.BytesUp, s.BytesDown, s.Packets = 3000, 4000, 40 // 7000 字节，超过降噪阈值

	e1 := New(cfg)
	if err := e1.AttachStore(st); err != nil {
		t.Fatal(err)
	}
	e1.Ingest(s)
	if err := e1.Flush(); err != nil {
		t.Fatal(err)
	}
	// Flush 必须把增量基准写进 session_offsets：这是重启后唯一的依据。
	if offs, err := st.SessionOffsets(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	} else if len(offs) != 1 {
		t.Fatalf("Flush 应落 1 条增量基准，实际 %d 条", len(offs))
	}
	before := totalEdgeBytes(t, e1)
	if before != 7000 {
		t.Fatalf("首次摄入后边字节应为 7000，实际 %d", before)
	}

	// ---- 重启：同一个库，新引擎 ----
	e2 := New(cfg)
	if err := e2.AttachStore(st); err != nil {
		t.Fatal(err)
	}
	// 探针重报同一条仍在持续的会话，累计值没变
	e2.Ingest(s)

	if got := totalEdgeBytes(t, e2); got != before {
		t.Fatalf("重启后同一会话不应重复计入：重启前 %d，重启后 %d（基准丢失会让流量翻倍）",
			before, got)
	}

	// 会话继续增长 1000 字节：只应加上这 1000
	grown := *s
	grown.BytesUp = 4000
	grown.LastSeen = s.LastSeen.Add(30 * time.Second)
	e2.Ingest(&grown)
	if got := totalEdgeBytes(t, e2); got != before+1000 {
		t.Fatalf("重启后增量应为 1000：期望 %d，实际 %d", before+1000, got)
	}
}

// 没有会话表数据的库（老库/首次启动）不能因为恢复失败而拒绝启动。
func TestRestoreWithoutSessionRowsStillStarts(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	e := New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("空库启动不应失败: %v", err)
	}
	e.Ingest(sessionTo("10.1.1.10", "10.1.1.20", 50001, 80, "tcp", base))
	if totalEdgeBytes(t, e) == 0 {
		t.Fatal("空库恢复后仍应能正常摄入")
	}
}

func totalEdgeBytes(t *testing.T, e *Engine) int64 {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	var sum int64
	for _, ed := range e.edges {
		sum += ed.Bytes
	}
	return sum
}
