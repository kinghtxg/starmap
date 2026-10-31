package topology

// 并发落盘回归测试（V1.5.2 新增）。
//
// 背景：V1.5.1 的 Flush 在 e.mu.Unlock() 之后又遍历 e.sessions 清 dirty 标记，
// 而抓包侧此时正往这张 map 里插新五元组。Go 运行时对"边读边写同一张 map"
// 直接抛 fatal error: concurrent map read and map write —— 这是**不可恢复**的，
// recover() 拦不住，整个服务进程当场退出。
//
// 这个缺陷逃过了全部 22 个包的既有测试，原因很简单：那些测试要么只测纯内存引擎、
// 要么只测引擎的单个方法，没有任何一个把"绑定存储 + 并发摄入 + 周期性 flush"
// 这三件事同时跑起来。本文件补的就是这个组合。
//
// 失败形态提醒：如果回归，这里报的不是 t.Fatal，而是整个 test binary 被 runtime
// 打死（输出里出现 fatal error: concurrent map read and map write）。这是预期形态，
// 说明改动确实把锁外访问 e.sessions 又引回来了。

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
)

// newRaceEngine 建一个绑定「内存库」的引擎。
//
// 这里刻意不用文件库（openTestStore）：本用例要反复 flush 上万条会话基准，
// 文件库的提交开销会把 2 秒的用例拖成 40 秒，而这条用例要验证的是并发，
// 不是 SQLite 的写吞吐。内存库同样走完整的 store 代码路径，语义一致。
func newRaceEngine(t *testing.T) *Engine {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("打开内存库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := New(model.SystemConfig{
		AgingSeconds:       3600,
		AggregateThreshold: 5,
		NoiseBytes:         1,
		NoisePackets:       1,
	})
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("绑定存储失败: %v", err)
	}
	return e
}

// seedSessions 预置 n 条不同五元组的会话，让一次 flush 的脏集合足够大。
// 脏集合越大，锁外那段遍历越久，与 map 扩容撞车的概率越高——这正是线上崩溃的成因。
func seedSessions(e *Engine, n int, ts time.Time) {
	for i := 0; i < n; i++ {
		e.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{
				SrcIP:   fmt.Sprintf("10.7.%d.%d", i/256%256, i%256),
				DstIP:   "8.8.4.4",
				SrcPort: uint16(1024 + i%60000),
				DstPort: 443,
				Proto:   "tcp",
			},
			BytesUp: 5000, BytesDown: 5000, Packets: 10,
			FirstSeen: ts, LastSeen: ts,
		})
	}
}

// TestFlushConcurrentWithIngest 是 V1.5.1 崩溃的直接回归门禁。
// 在修复前的代码上跑，约 0.3~3 秒内必然出现 fatal error（本机 3/3 复现）。
func TestFlushConcurrentWithIngest(t *testing.T) {
	e := newRaceEngine(t)
	now := time.Now()
	seedSessions(e, 20000, now)

	var stop int32
	var wg sync.WaitGroup

	// 写入方：反复触摸预置的那批会话（让**每一次** flush 的脏集合都很大），
	// 同时持续插入少量新键（让 map 在读取期间发生扩容）。
	//
	// 这里的关键是"每轮 flush 的 offs 都要够大"。如果只写新键，dirty 集合
	// 每轮只有几十条，读循环太短、撞上写入的概率就低——实测这样做的门禁
	// 漏检率约三分之一，不能当闸门用。
	//
	// 用固定的键空间而不是自增：不限速地自增一秒钟能造出几十万条会话，
	// 每次 flush 都要写几十万行，用例会退化成在测 SQLite。
	const existing = 20000
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; atomic.LoadInt32(&stop) == 0; i++ {
			// 触摸已有会话：标脏 + 让 e.sessions 被写入
			e.Ingest(&model.Session{
				FiveTuple: model.FiveTuple{
					SrcIP:   fmt.Sprintf("10.7.%d.%d", (i%existing)/256, i%256),
					DstIP:   "8.8.4.4",
					SrcPort: uint16(1024 + i%60000), DstPort: 443, Proto: "tcp",
				},
				BytesUp: 6000, BytesDown: 6000, Packets: 12,
				FirstSeen: now, LastSeen: now,
			})
			// 每 64 轮插一个新键：键空间有上限（5000），扩容集中在前段发生
			if i%64 == 0 {
				e.Ingest(&model.Session{
					FiveTuple: model.FiveTuple{
						SrcIP:   fmt.Sprintf("172.20.%d.%d", i/64/256%256, i/64%256),
						DstIP:   "1.1.1.1",
						SrcPort: uint16(2000 + i%60000), DstPort: 80, Proto: "tcp",
					},
					BytesUp: 4000, BytesDown: 4000, Packets: 8,
					FirstSeen: now, LastSeen: now,
				})
			}
		}
	}()

	// 落盘方：比生产节奏（2s）密两个数量级，让窗口反复暴露
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt32(&stop) == 0 {
			if err := e.Flush(); err != nil {
				t.Errorf("落盘失败: %v", err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	time.Sleep(2 * time.Second)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()

	// 走到这里说明没有 fatal；再确认一次收尾 flush 仍然正常
	if err := e.Flush(); err != nil {
		t.Fatalf("收尾落盘失败: %v", err)
	}
}

// TestFlushClearsDirtyUnderLock 验证"写完库之后不会再回头去 map 里改 dirty"。
// 判据：连续两次 flush，第二次必须是空操作（没有任何脏会话）——
// 如果 dirty 没被清干净，第二次还会再写一遍。
func TestFlushClearsDirtyUnderLock(t *testing.T) {
	e := newRaceEngine(t)
	now := time.Now()
	seedSessions(e, 500, now)

	if err := e.Flush(); err != nil {
		t.Fatalf("首次落盘失败: %v", err)
	}

	e.mu.RLock()
	dirty := 0
	for _, ss := range e.sessions {
		if ss != nil && ss.dirty {
			dirty++
		}
	}
	pending := e.sessionDirty
	e.mu.RUnlock()

	if dirty != 0 || pending {
		t.Fatalf("首次落盘后仍有 %d 条会话处于脏状态（sessionDirty=%v），说明 dirty 没有被清掉", dirty, pending)
	}
}

// TestSessionBaselinePrunedFromMemory 验证 e.sessions 有回收路径（V1.5.1 完全没有）。
func TestSessionBaselinePrunedFromMemory(t *testing.T) {
	e := newRaceEngine(t)
	now := time.Now()
	seedSessions(e, 20000, now)

	e.mu.RLock()
	before := len(e.sessions)
	e.mu.RUnlock()
	if before == 0 {
		t.Fatal("预置会话失败，基准为空")
	}

	// 把所有基准的"最后见过时间"推到 24 小时前，然后允许立即修剪
	old := now.Add(-24 * time.Hour)
	e.mu.Lock()
	for _, ss := range e.sessions {
		ss.seenAt = old
	}
	e.lastPrune = time.Time{}
	e.mu.Unlock()

	e.pruneOffsets(e.persist)

	e.mu.RLock()
	after := len(e.sessions)
	e.mu.RUnlock()

	if after != 0 {
		t.Fatalf("过期基准未被回收：修剪前 %d 条，修剪后仍剩 %d 条。"+
			"聚合器早已回收这些会话，引擎侧却永久留着 key —— 这就是长跑内存只增不减的根因。", before, after)
	}
}

// TestSessionBaselineKeepsFresh 修剪不能误伤仍然活跃的会话。
func TestSessionBaselineKeepsFresh(t *testing.T) {
	e := newRaceEngine(t)
	now := time.Now()
	seedSessions(e, 100, now)

	e.mu.Lock()
	e.lastPrune = time.Time{}
	e.mu.Unlock()
	e.pruneOffsets(e.persist)

	e.mu.RLock()
	after := len(e.sessions)
	e.mu.RUnlock()
	if after != 100 {
		t.Fatalf("刚刚摄入、仍然活跃的会话基准被误删：期望 100，实际 %d", after)
	}
}
