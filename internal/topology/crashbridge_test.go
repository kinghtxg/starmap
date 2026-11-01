package topology

import (
	"path/filepath"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
)

// 本文件守的是 1.7.0 这次"重启翻倍"修补里最容易被改坏的两件事：
//
//  1. 新会话的增量基准必须**马上**落库（快档），不能等 60 秒的计数刷新；
//  2. 底数确实丢了的时候（强杀、掉电、OOM），必须能认出"这是一条跨进程启动的
//     在途会话"，按当前快照当底数，而不是把整笔流量再算一遍。
//
// 两件事都很难靠人工看代码发现：第一种只在强杀时暴露，第二种只在崩溃重启后暴露，
// 而它们的共同表现是"总流量的数字变大了"——没有任何报错。

// crashStore 打开一个临时文件库。
func crashStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "crash.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// wipeOffsets 清掉全部增量基准，模拟"进程被强杀，来不及落盘"。
func wipeOffsets(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.PruneSessionOffsets(time.Now().Add(24 * time.Hour)); err != nil {
		t.Fatalf("清理增量基准: %v", err)
	}
	if offs, err := st.SessionOffsets(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	} else if len(offs) != 0 {
		t.Fatalf("预期基准已清空，实际还剩 %d 条", len(offs))
	}
}

// liveSession 造一条"现在还在跑"的会话：FirstSeen 在一分钟前，LastSeen 就是现在。
// 只在本文件里用，避免每条用例重复三行赋值。
func liveSession(s *model.Session, now time.Time) *model.Session {
	s.FirstSeen, s.LastSeen = now.Add(-time.Minute), now
	s.BytesUp, s.BytesDown, s.Packets = 3000, 4000, 40 // 7000 字节，稳过降噪阈值
	return s
}

// TestNewSessionBaselineLandsInFastTier 新会话的底数不能等 60 秒那一档。
//
// 快档（includeCounters=false）原本只写"结构变更"，会话基准要等 60 秒的计数档。
// 于是新会话有最多 60 秒完全没有底数——强杀正好落在这个窗口里就是整笔重复计入。
func TestNewSessionBaselineLandsInFastTier(t *testing.T) {
	st := crashStore(t)
	e := New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}

	now := time.Now()
	s := liveSession(sessionTo("10.9.9.10", "10.9.9.20", 51001, 445, "tcp", now), now)
	e.Ingest(s)

	// 快档：只跑一拍结构落盘
	if err := e.flush(false); err != nil {
		t.Fatalf("flush(false): %v", err)
	}
	offs, err := st.SessionOffsets(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	}
	if len(offs) != 1 {
		t.Fatalf("新会话的底数应在第一拍就落库，实际落库 %d 条", len(offs))
	}

	// 已经落过库的会话不再进快档：值继续长，但数据库里仍是旧值，
	// 直到 60 秒那一档才刷新。这样稳态下每拍写的行数只跟"新会话速率"有关。
	grown := *s
	grown.BytesUp, grown.BytesDown = 9000, 9000
	grown.LastSeen = now.Add(10 * time.Second)
	e.Ingest(&grown)
	if err := e.flush(false); err != nil {
		t.Fatalf("flush(false) 第二次: %v", err)
	}
	again, err := st.SessionOffsets(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	}
	if len(again) != 1 || again[s.FiveTuple.Key()].Bytes != 7000 {
		t.Fatalf("快档不应重复刷新已落库的底数：%+v", again)
	}

	// 慢档（全量计数刷新）才把新值写进去
	if err := e.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	full, err := st.SessionOffsets(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	}
	if got := full[s.FiveTuple.Key()].Bytes; got != 18000 {
		t.Fatalf("慢档应把累计值刷成 18000，实际 %d", got)
	}
}

// TestCrashBridgeDoesNotDoubleCountBytes 底数丢了之后，跨进程启动的在途会话
// 只能按"当前快照即底数"处理，不能整笔重算。
//
// 复现路径（线上实测）：上报一条 1,000,000 字节的会话 → 任务管理器结束进程
// → 重启 → 同一份快照再报一次 → 总流量又涨 1,000,000。
func TestCrashBridgeDoesNotDoubleCountBytes(t *testing.T) {
	st := crashStore(t)
	cfg := testCfg()

	e1 := New(cfg)
	if err := e1.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	now := time.Now()
	s := liveSession(sessionTo("10.8.8.10", "10.8.8.20", 52001, 445, "tcp", now), now)
	e1.Ingest(s)
	if err := e1.Flush(); err != nil { // 边落盘了
		t.Fatalf("Flush: %v", err)
	}
	before := totalEdgeBytes(t, e1)
	if before != 7000 {
		t.Fatalf("首次摄入后边字节应为 7000，实际 %d", before)
	}
	// 强杀：边还在库里，基准全丢
	wipeOffsets(t, st)

	e2 := New(cfg)
	if err := e2.AttachStore(st); err != nil {
		t.Fatalf("重启后 AttachStore: %v", err)
	}
	if got := totalEdgeBytes(t, e2); got != before {
		t.Fatalf("重启应完整恢复边字节：期望 %d，实际 %d", before, got)
	}
	// 探针重报同一条仍在持续的会话（累计值没变）
	e2.Ingest(s)
	if got := totalEdgeBytes(t, e2); got != before {
		t.Fatalf("基准丢失后重报同一会话不应重复计入：%d → %d", before, got)
	}

	// 之后继续增长 500 字节：只加这 500，不能多也不能少
	grown := *s
	grown.BytesUp = 3500
	grown.LastSeen = s.LastSeen.Add(30 * time.Second)
	e2.Ingest(&grown)
	if got := totalEdgeBytes(t, e2); got != before+500 {
		t.Fatalf("崩溃兜底之后增量应为 500：期望 %d，实际 %d", before+500, got)
	}
}

// TestHistoricalImportIsNotSwallowed 导入历史 PCAP 不能被崩溃兜底误伤。
//
// 兜底判据里"LastSeen 不早于本次启动"这一条是关键：历史数据的两端时间戳
// 都来自报文本身、都在过去。若只判 FirstSeen，导入 pcap 的流量会被当成
// "上个进程的遗产"而一笔不记——那是数据消失，比数字偏大严重得多。
func TestHistoricalImportIsNotSwallowed(t *testing.T) {
	st := crashStore(t)
	e := New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	// 一年前的会话：FirstSeen 与 LastSeen 都早于本次启动
	s := sessionTo("10.7.7.10", "10.7.7.20", 53001, 445, "tcp", base)
	e.Ingest(s)
	if got := totalEdgeBytes(t, e); got != 3000 {
		t.Fatalf("导入历史 PCAP 必须照常计入：期望 3000（sessionTo 默认值），实际 %d", got)
	}
}

// TestFreshSessionOnColdStartStillCounted 冷启动后的第一份快照照常计入。
//
// 兜底只该覆盖"跨进程启动"的那一类。会话从本次启动之后才开始（FirstSeen 晚于
// 启动时间）时，它的字节就是本进程的增量，必须全额计入。
func TestFreshSessionOnColdStartStillCounted(t *testing.T) {
	st := crashStore(t)
	e := New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	now := time.Now()
	s := sessionTo("10.6.6.10", "10.6.6.20", 54001, 445, "tcp", now)
	s.FirstSeen, s.LastSeen = now.Add(-time.Second), now
	e.Ingest(s)
	if got := totalEdgeBytes(t, e); got != 3000 {
		t.Fatalf("本次启动后才开始的会话应全额计入：期望 3000（sessionTo 默认值），实际 %d", got)
	}
}

// TestOffsetFlushBatchIsBounded 快档必须限流：一次爆发式灌库不能把一拍拖成秒级。
func TestOffsetFlushBatchIsBounded(t *testing.T) {
	st := crashStore(t)
	e := New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	now := time.Now()
	n := offsetFlushBatch + 500
	for i := 0; i < n; i++ {
		// 端口当序号用，造 n 条互不相同的会话
		s := liveSession(sessionTo("10.5.0.10", "10.5.0.20", uint16(10000+i%50000), uint16(80+i%1000), "tcp", now), now)
		e.Ingest(s)
	}
	if err := e.flush(false); err != nil {
		t.Fatalf("flush(false): %v", err)
	}
	first, err := st.SessionOffsets(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	}
	if len(first) != offsetFlushBatch {
		t.Fatalf("单拍应写入 offsetFlushBatch=%d 条，实际 %d 条", offsetFlushBatch, len(first))
	}
	// 下一拍把剩下的补上
	if err := e.flush(false); err != nil {
		t.Fatalf("flush(false) 第二次: %v", err)
	}
	second, err := st.SessionOffsets(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("SessionOffsets: %v", err)
	}
	if len(second) <= len(first) {
		t.Fatalf("剩余会话应在后续拍次继续落库：第一拍 %d，第二拍 %d", len(first), len(second))
	}
}
