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

// TestCrashBridgeSkipsHistoryOnRestart 崩溃重启后，在途会话的首份快照不能再计一遍。
//
// 场景：上一个进程已经落过盘（库里留有基准），某条会话在它被强杀时还没轮到落基准，
// 重启后探针照旧上报这条会话的累计值。累计值里那一段历史**已经被上一个进程计入过边**，
// 再整笔加一次就是"重启一次流量翻一倍"——界面上只是数字变大，没有任何地方报错。
//
// 判据的前置条件是"库里恢复出了基准"，不是"库里有数据"：一条基准都没有的全新库上，
// 那些字节从来没被任何人计入过，按遗留丢掉首份快照就是纯丢数据
// （TestRestartDoesNotDoubleCountBytes 的第一段断言守的正是这条反例）。
func TestCrashBridgeSkipsHistoryOnRestart(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "bridge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := testCfg()
	now := time.Now().UTC()

	// 上一个进程：另一条会话落过基准，这就是"库里有过历史"的证据
	prev := sessionTo("10.3.3.10", "10.3.3.20", 41001, 445, "tcp", base)
	prev.FirstSeen, prev.LastSeen = now.Add(-2*time.Minute), now
	prev.BytesUp, prev.BytesDown, prev.Packets = 5000, 5000, 50
	e0 := New(cfg)
	if err := e0.AttachStore(st); err != nil {
		t.Fatal(err)
	}
	e0.Ingest(prev)
	if err := e0.Flush(); err != nil {
		t.Fatal(err)
	}

	// ---- 重启：新引擎接回上一个进程的边与基准 ----
	e1 := New(cfg)
	if err := e1.AttachStore(st); err != nil {
		t.Fatal(err)
	}
	baseline := totalEdgeBytes(t, e1)
	if baseline == 0 {
		t.Fatal("重启后应恢复出上一个进程的边（本用例的前提），实际 0")
	}
	if e1.restoredOffsets == 0 {
		t.Fatal("应恢复出至少一条增量基准（crashBridge 的前置条件），实际 0")
	}

	// 在途会话：启动前就在传，强杀时基准没来得及落盘
	s := sessionTo("10.3.3.30", "10.3.3.40", 41002, 445, "tcp", base)
	s.FirstSeen, s.LastSeen = now.Add(-5*time.Minute), time.Now()
	s.BytesUp, s.BytesDown, s.Packets = 3000000, 4000000, 4000
	e1.Ingest(s)
	if got := totalEdgeBytes(t, e1); got != baseline {
		t.Fatalf("重启后首份快照不应计入：重启前 %d，摄入后 %d（应仍为 %d）", baseline, got, baseline)
	}

	// 之后继续增长 1000 字节：只加这 1000（说明它已经以当前快照为底数了）
	grown := *s
	grown.BytesUp += 1000
	grown.LastSeen = time.Now()
	e1.Ingest(&grown)
	if got := totalEdgeBytes(t, e1); got != baseline+1000 {
		t.Fatalf("后续增量应为 1000：期望 %d，实际 %d", baseline+1000, got)
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
