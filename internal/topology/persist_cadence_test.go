// 落盘两档节奏的护栏（V1.6）。
//
// 起因：每 2 秒把整份变化集重写一遍（节点 last_seen、边字节数、会话增量基准）。
// 6 万节点的网络 = 30k 行/秒的持续写入，SQLite 只有一个写者，写锁被这件事占满，
// 探针上报排队到 3.4 秒。改成两档后必须保证两件事：
//
//  1. 结构变更（新节点/新边）走快通道，2 秒内一定落盘——否则重启会少设备；
//  2. 纯计数刷新走慢通道，不该在快通道里被写出去——否则等于没改。
//
// 这两条都是"不报错但错得很难发现"的类型：丢结构要等重启才发现，
// 多写则只表现为"跑一会儿就变卡"。所以必须有断言，不能靠看日志。
package topology

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
)

func newPersistEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/persist.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	e := New(model.SystemConfig{AgingSeconds: 3600, AggregateThreshold: 1000})
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("绑定存储失败: %v", err)
	}
	return e, st
}

func sess(src, dst, mac string, port uint16, at time.Time, bytes int64) *model.Session {
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: src, DstIP: dst, SrcPort: port, DstPort: 443, Proto: "tcp"},
		MAC:       mac, FirstSeen: at, LastSeen: at,
		BytesUp: bytes / 2, BytesDown: bytes / 2, Packets: 10,
	}
}

// TestSlowFlushSkipsCounterOnlyChanges 纯计数变化不该被快通道写出去。
func TestSlowFlushSkipsCounterOnlyChanges(t *testing.T) {
	e, st := newPersistEngine(t)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.Local)

	e.Ingest(sess("10.0.0.1", "172.16.0.9", "aa:bb:cc:00:00:01", 40001, base, 10000))
	if err := e.flush(false); err != nil {
		t.Fatalf("首次落盘失败: %v", err)
	}
	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		t.Fatal("结构变更（新节点）必须在快通道落盘")
	}
	var firstSeen time.Time
	for _, n := range nodes {
		if n.IPs[0] == "10.0.0.1" {
			firstSeen = n.LastSeen
		}
	}
	if firstSeen.IsZero() {
		t.Fatal("节点 10.0.0.1 没有落盘")
	}

	// 同一条会话、时间更晚、字节更多 —— 只有计数在变。
	later := base.Add(30 * time.Minute)
	e.Ingest(sess("10.0.0.1", "172.16.0.9", "aa:bb:cc:00:00:01", 40001, later, 20000))
	if err := e.flush(false); err != nil {
		t.Fatalf("快通道落盘失败: %v", err)
	}
	nodes, _ = st.ListNodes()
	for _, n := range nodes {
		if n.IPs[0] == "10.0.0.1" && n.LastSeen.After(firstSeen) {
			t.Fatalf("纯 last_seen 变化不应走快通道（库里已更新为 %v）", n.LastSeen)
		}
	}

	// 慢通道必须把它写下去，否则 last_seen 永远停在第一次落盘。
	if err := e.flush(true); err != nil {
		t.Fatalf("慢通道落盘失败: %v", err)
	}
	nodes, _ = st.ListNodes()
	updated := false
	for _, n := range nodes {
		if n.IPs[0] == "10.0.0.1" && n.LastSeen.After(firstSeen) {
			updated = true
		}
	}
	if !updated {
		t.Fatal("慢通道必须刷新 last_seen，否则页面上的活跃时间会一直停在旧值")
	}
}

// TestFastFlushWritesNewEdges 新边属于结构变更，必须走快通道。
func TestFastFlushWritesNewEdges(t *testing.T) {
	e, st := newPersistEngine(t)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		e.Ingest(sess(fmt.Sprintf("10.0.1.%d", i+1), "172.16.0.9", fmt.Sprintf("aa:bb:cc:01:00:%02x", i+1), uint16(41000+i), base, 10000))
	}
	if err := e.flush(false); err != nil {
		t.Fatalf("快通道落盘失败: %v", err)
	}
	edges, err := st.ListEdges()
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 5 {
		t.Fatalf("5 条新会话应产生 5 条边并立即落盘，实际 %d 条", len(edges))
	}
}

// TestFlushBatchSizeBoundedByChanges 稳态下快通道不该产生写操作。
//
// 这是本次修复的核心指标：同一批会话反复上报（探针的真实行为）时，
// 快通道的待写集合必须为空——否则每 2 秒又把全表重写一遍。
func TestFlushBatchSizeBoundedByChanges(t *testing.T) {
	e, _ := newPersistEngine(t)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.Local)
	for i := 0; i < 500; i++ {
		e.Ingest(sess(fmt.Sprintf("10.0.2.%d", i%200+1), "172.16.0.9", fmt.Sprintf("aa:bb:cc:02:%02x:%02x", (i%200)/256, i%200), uint16(42000+i%200), base, 10000))
	}
	if err := e.flush(false); err != nil {
		t.Fatal(err)
	}
	// 再报一遍同样的会话（时间前进、字节增加）
	for i := 0; i < 500; i++ {
		e.Ingest(sess(fmt.Sprintf("10.0.2.%d", i%200+1), "172.16.0.9", fmt.Sprintf("aa:bb:cc:02:%02x:%02x", (i%200)/256, i%200), uint16(42000+i%200), base.Add(time.Minute), 20000))
	}
	e.mu.Lock()
	nDirty, eDirty := len(e.dirtyNodes), len(e.dirtyEdges)
	e.mu.Unlock()
	if nDirty != 0 || eDirty != 0 {
		t.Fatalf("重复上报不应产生结构变更，实际 dirtyNodes=%d dirtyEdges=%d", nDirty, eDirty)
	}
}
