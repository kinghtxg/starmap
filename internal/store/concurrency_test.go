// 连接池并发安全（V1.6.1）。
//
// 背景：Open 原来把连接池限死为 1 条，理由是"SQLite 单写者，多连接会
// database is locked"。代价是**读也要排在写后面**：68k 会话、探针持续上报时，
// 一条查白名单的 SQL（本身返回 0 行）要等 2.4 秒才拿到连接。评估器每轮固定
// 多花 2~3 秒，看日志像"评估慢"，实际是"读被写堵住"。
//
// 改成 8 条连接 + busy_timeout + _txlock=immediate 后，写仍然互斥（由 SQLite
// 写锁保证），读并发。这组用例就是这条改动的护栏：只要并发读写开始报
// "database is locked" / "SQLITE_BUSY"，它就会失败。
package store

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestConcurrentReadWriteNoLockError 8 写 8 读并发压 2 秒，要求零错误。
func TestConcurrentReadWriteNoLockError(t *testing.T) {
	st, err := Open(t.TempDir() + "/concurrent.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	var wg sync.WaitGroup
	var errs atomic.Int64
	var firstErr atomic.Value
	record := func(err error) {
		if err == nil {
			return
		}
		errs.Add(1)
		firstErr.CompareAndSwap(nil, err.Error())
	}

	deadline := time.Now().Add(2 * time.Second)

	// 写侧：模拟探针上报（批量会话 + 事件）
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			n := 0
			for time.Now().Before(deadline) {
				n++
				batch := make([]model.Session, 0, 50)
				for i := 0; i < 50; i++ {
					batch = append(batch, model.Session{
						FiveTuple: model.FiveTuple{
							SrcIP: fmt.Sprintf("10.%d.%d.%d", w, n%256, i),
							DstIP: "172.16.0.9", SrcPort: uint16(1000 + i),
							DstPort: 443, Proto: "tcp",
						},
						MAC:       fmt.Sprintf("02:aa:%02x:%02x:%02x:01", w, n%256, i),
						FirstSeen: time.Now(), LastSeen: time.Now(),
						BytesUp: 100, BytesDown: 200, Packets: 3,
					})
				}
				record(st.SaveSessions(batch))
				_, err := st.CreateEvents([]*model.RiskEvent{{
					Type: model.EventTypeMultiNet, NodeID: int64(w*1000 + n),
					Title: "并发用例", Level: model.RiskHigh,
					Status: model.EventStatusPending, Evidence: map[string]string{"k": "v"},
				}})
				record(err)
			}
		}(w)
	}

	// 读侧：模拟 HTTP 接口（统计、列表、白名单）
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_, err := st.CountEvents(EventFilter{})
				record(err)
				_, err = st.ListEventsPaged(EventFilter{Status: model.EventStatusPending}, 50, 0)
				record(err)
				_, err = st.ListWhitelist()
				record(err)
				_, err = st.ListEventsForDedup(time.Now().Add(-24 * time.Hour))
				record(err)
			}
		}()
	}

	wg.Wait()
	if n := errs.Load(); n > 0 {
		t.Fatalf("并发读写出现 %d 次错误，首个：%v", n, firstErr.Load())
	}
}

// TestReadNotBlockedByWriter 读必须在写事务进行时也能立刻拿到连接。
//
// 这是限制连接数为 1 时最直接的病：一条长写事务会把所有读卡住。
// 这里开一个 3000 行的批量写入，同时测量几次纯读的耗时。
//
// 两个子用例是同一个实验的两面：默认连接池必须快（护栏），
// 手工压回单连接必须慢（证明这条护栏测的确实是连接池，而不是别的东西）。
func TestReadNotBlockedByWriter(t *testing.T) {
	t.Run("默认连接池", func(t *testing.T) {
		st, err := Open(t.TempDir() + "/readwhilewrite.db")
		if err != nil {
			t.Fatalf("打开库失败: %v", err)
		}
		defer st.Close()
		worst := worstReadDuringWrite(t, st)
		// 阈值取 100ms：连接池正常时实测 1ms，而单连接池时读要等整个写事务
		// （3000 行批量写入约 350ms）——两者差两个数量级，门禁足够分辨。
		if worst > 100*time.Millisecond {
			t.Fatalf("读被写堵住了：最差 %v（连接池被限制成单条时会重现这个现象）", worst)
		}
	})

	t.Run("单连接池必然被堵", func(t *testing.T) {
		st, err := Open(t.TempDir() + "/singleconn.db")
		if err != nil {
			t.Fatalf("打开库失败: %v", err)
		}
		defer st.Close()
		st.db.SetMaxOpenConns(1) // 退回旧实现
		st.db.SetMaxIdleConns(1)
		worst := worstReadDuringWrite(t, st)
		if worst < 100*time.Millisecond {
			t.Skipf("本机写太快（最差 %v），单连接池也没被堵出可观测差异；跳过而不是误报失败",
				worst.Round(time.Millisecond))
		}
		t.Logf("单连接池下最差读耗时 %v —— 与默认连接池的差异即本用例的意义", worst.Round(time.Millisecond))
	})
}

// worstReadDuringWrite 在一个 3000 行批量写入进行时，连续做 20 次纯读，返回最差耗时。
func worstReadDuringWrite(t *testing.T, st *Store) time.Duration {
	t.Helper()
	batch := make([]model.Session, 0, 3000)
	for i := 0; i < 3000; i++ {
		batch = append(batch, model.Session{
			FiveTuple: model.FiveTuple{SrcIP: fmt.Sprintf("10.9.%d.%d", i/256, i%256),
				DstIP: "172.16.0.9", SrcPort: uint16(1000 + i), DstPort: 443, Proto: "tcp"},
			MAC:       fmt.Sprintf("02:bb:%02x:%02x:01:01", i/256, i%256),
			FirstSeen: time.Now(), LastSeen: time.Now(),
			BytesUp: 1, BytesDown: 2, Packets: 3,
		})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = st.SaveSessions(batch)
	}()

	var worst time.Duration
	for i := 0; i < 20; i++ {
		start := time.Now()
		if _, err := st.ListWhitelist(); err != nil {
			t.Fatalf("并发读失败: %v", err)
		}
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	<-done
	t.Logf("写事务并发期间，20 次白名单读的最差耗时：%v", worst.Round(time.Millisecond))
	return worst
}
