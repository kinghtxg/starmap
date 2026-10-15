package topology_test

import (
	"path/filepath"
	"testing"
	"time"

	"starmap/internal/detect"
	"starmap/internal/model"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// openStoreFile 用真实文件库（需验证跨进程重启，":memory:" 无法复用）。
func openStoreFile(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "topo.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
	}
}

// newPersistentEngine 建一个已绑定持久化并恢复过拓扑的引擎。
func newPersistentEngine(t *testing.T, st *store.Store) *topology.Engine {
	t.Helper()
	e := topology.New(testCfg())
	if err := e.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	return e
}

func frpSession(srcIP, mac, dstIP string, port uint16) *model.Session {
	now := time.Now()
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: srcIP, DstIP: dstIP, SrcPort: port, DstPort: 443, Proto: "tcp"},
		MAC:       mac,
		FirstSeen: now, LastSeen: now,
		BytesUp: 5000, BytesDown: 5000, Packets: 30,
	}
}

// TestPersistRestartRestore 核心回归（P0-2）：拓扑持久化后"重启"可完整恢复，
// 节点 ID / NodeKey / 边全部对齐，历史事件的 node_id 不再是孤儿。
func TestPersistRestartRestore(t *testing.T) {
	st := openStoreFile(t)

	e1 := newPersistentEngine(t, st)
	e1.Ingest(frpSession("192.168.1.10", "aa:bb:cc:dd:ee:01", "203.0.113.7", 1111))
	e1.Ingest(frpSession("192.168.1.20", "", "198.51.100.9", 2222))
	if err := e1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	n1 := e1.NodeByIP("192.168.1.10")
	n2 := e1.NodeByIP("192.168.1.20")
	if n1 == nil || n2 == nil {
		t.Fatal("两个内网节点都应存在")
	}
	// 历史事件绑定 n1
	ev := &model.RiskEvent{Type: model.EventTypeFRP, NodeID: n1.ID, Title: "t", Level: model.RiskMid}
	if _, err := st.CreateEvent(ev); err != nil {
		t.Fatal(err)
	}

	// ---- 模拟进程重启：同一份库重建引擎 ----
	e2 := newPersistentEngine(t, st)

	got1 := e2.NodeByIP("192.168.1.10")
	got2 := e2.NodeByIP("192.168.1.20")
	if got1 == nil || got2 == nil {
		t.Fatalf("重启后节点丢失: n1=%+v n2=%+v", got1, got2)
	}
	if got1.ID != n1.ID || got2.ID != n2.ID {
		t.Fatalf("重启后节点 ID 漂移: %d→%d, %d→%d", n1.ID, got1.ID, n2.ID, got2.ID)
	}
	if got1.NodeKey != n1.NodeKey || got1.NodeKey != "mac:aa:bb:cc:dd:ee:01" {
		t.Fatalf("NodeKey 应以 MAC 为准且跨重启稳定: %q → %q", n1.NodeKey, got1.NodeKey)
	}
	if got2.NodeKey != n2.NodeKey || got2.NodeKey != "ip:192.168.1.20" {
		t.Fatalf("无 MAC 节点应以主 IP 为 NodeKey: %q → %q", n2.NodeKey, got2.NodeKey)
	}
	if got1.MAC != "aa:bb:cc:dd:ee:01" || got1.Domain != n1.Domain {
		t.Fatalf("重启后节点属性不一致: %+v", got1)
	}
	// 外部聚合节点也应一并恢复
	if e2.NodeByExternalCIDR("203.0.113.0/24") == nil || e2.NodeByExternalCIDR("198.51.100.0/24") == nil {
		t.Fatal("外部聚合节点应持久化并恢复")
	}
	// 边：幂等键 (src_key,dst_key,protocol)，重复 flush 不应增生
	before := e1.SnapshotEdgePairs()
	after := e2.SnapshotEdgePairs()
	if len(after) != len(before) || len(after) != 2 {
		t.Fatalf("边的数量应一致且为 2: before=%d after=%d", len(before), len(after))
	}
	var totalBefore, totalAfter int64
	for _, e := range before {
		totalBefore += e.Bytes
	}
	for _, e := range after {
		totalAfter += e.Bytes
	}
	if totalAfter != totalBefore || totalAfter != 20000 {
		t.Fatalf("边流量应完整恢复: %d vs %d", totalBefore, totalAfter)
	}
	// 历史事件不再是孤儿
	if n := e2.GetNode(ev.NodeID); n == nil || n.NodeKey != n1.NodeKey {
		t.Fatalf("历史事件 node_id 应仍指向同一节点: %+v", n)
	}
	// ID 自增从库内最大值继续，不会与历史节点撞号
	fresh := e2.NodeByIP("192.168.1.99")
	if fresh != nil {
		t.Fatal("新引擎不应凭空出现节点")
	}
	e2.Ingest(frpSession("192.168.1.99", "aa:bb:cc:dd:ee:09", "203.0.113.7", 3333))
	fresh = e2.NodeByIP("192.168.1.99")
	if fresh == nil || fresh.ID <= got1.ID || fresh.ID <= got2.ID {
		t.Fatalf("新节点 ID 应大于库内历史最大值: %+v", fresh)
	}
}

// TestPersistFlushIdempotent 重复 flush 不应让库里出现重复节点/边。
func TestPersistFlushIdempotent(t *testing.T) {
	st := openStoreFile(t)
	e := newPersistentEngine(t, st)
	e.Ingest(frpSession("192.168.1.30", "aa:bb:cc:dd:ee:03", "203.0.113.7", 4444))
	for i := 0; i < 5; i++ {
		if err := e.Flush(); err != nil {
			t.Fatalf("Flush#%d: %v", i, err)
		}
	}
	// 同一 session 重复 Ingest（内部幂等增量），再 flush
	e.Ingest(frpSession("192.168.1.30", "aa:bb:cc:dd:ee:03", "203.0.113.7", 4444))
	if err := e.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 { // 内网节点 + 外部聚合节点
		t.Fatalf("重复 flush 后出现重复节点: %+v", nodes)
	}
	edges, err := st.ListEdges()
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("重复 flush 后边应仍只有 1 条: %+v", edges)
	}
	if edges[0].Bytes != 10000 {
		t.Fatalf("同会话重复摄入不应重复累加流量: %d", edges[0].Bytes)
	}
}

// TestWhitelistNodeKeyAcrossRestart 白名单 node 维度跨重启不错配（P0-2 最危险的后半段）：
// 误报生成的 node 白名单在重启后必须仍只命中原节点，且不会落到别的节点上。
func TestWhitelistNodeKeyAcrossRestart(t *testing.T) {
	st := openStoreFile(t)

	// ---- 第一次运行：两台主机发言，复核 192.168.1.40 为误报 → 自动加白 ----
	e1 := newPersistentEngine(t, st)
	e1.Ingest(frpSession("192.168.1.40", "aa:bb:cc:dd:ee:40", "203.0.113.7", 5001))
	e1.Ingest(frpSession("192.168.1.41", "aa:bb:cc:dd:ee:41", "203.0.113.7", 5002))
	if err := e1.Flush(); err != nil {
		t.Fatal(err)
	}
	victim := e1.NodeByIP("192.168.1.40")
	other := e1.NodeByIP("192.168.1.41")

	rvw := review.New(st, e1)
	ev := &model.RiskEvent{Type: model.EventTypeFRP, NodeID: victim.ID, Title: "t", Level: model.RiskMid}
	evID, err := st.CreateEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rvw.Review(evID, review.ActionFalsePositive, "内网堡垒机", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := e1.Flush(); err != nil {
		t.Fatal(err)
	}

	var nodeKey string
	list, err := st.ListWhitelist()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range list {
		if w.Kind == "node" && w.Value == victim.NodeKey {
			nodeKey = w.Value
		}
	}
	if nodeKey == "" {
		t.Fatalf("误报应写入 node:<node_key> 条目，实际: %+v", list)
	}

	// ---- 重启：拓扑从库恢复 ----
	e2 := newPersistentEngine(t, st)

	entry := model.WhitelistEntry{Kind: "node", Value: nodeKey}
	for _, tc := range []struct {
		name string
		id   int64
		want bool
	}{
		{"加白原节点", victim.ID, true},
		{"不误伤其它节点", other.ID, false},
	} {
		node := e2.GetNode(tc.id)
		evHit := &model.RiskEvent{NodeID: tc.id, Evidence: map[string]string{"src_ip": ""}}
		if got := detect.MatchWhitelist(entry, evHit, node); got != tc.want {
			t.Fatalf("%s: node 维度匹配应=%v 实际=%v（node=%+v）", tc.name, tc.want, got, node)
		}
	}
	// 全部条目的聚合匹配也不能错配
	if detect.MatchAnyWhitelist(list, &model.RiskEvent{NodeID: other.ID, Evidence: map[string]string{}}, e2.GetNode(other.ID)) {
		t.Fatalf("无关节点被白名单命中（静默抑制）: %+v", list)
	}
	if !detect.MatchAnyWhitelist(list, &model.RiskEvent{NodeID: victim.ID, Evidence: map[string]string{}}, e2.GetNode(victim.ID)) {
		t.Fatalf("原节点应被白名单命中: %+v", list)
	}
}

// TestWhitelistLegacyNumericNodeIDBackwardCompat V1.0 遗留的 node:<数字 id> 条目仍能命中
// （节点已持久化并按原 ID 恢复），且不会退化成"永不命中"。
func TestWhitelistLegacyNumericNodeIDBackwardCompat(t *testing.T) {
	st := openStoreFile(t)
	e1 := newPersistentEngine(t, st)
	e1.Ingest(frpSession("192.168.1.50", "aa:bb:cc:dd:ee:50", "203.0.113.7", 6001))
	if err := e1.Flush(); err != nil {
		t.Fatal(err)
	}
	n := e1.NodeByIP("192.168.1.50")

	e2 := newPersistentEngine(t, st)
	legacy := model.WhitelistEntry{Kind: "node", Value: itoa(n.ID)}
	ev := &model.RiskEvent{NodeID: n.ID, Evidence: map[string]string{}}
	if !detect.MatchWhitelist(legacy, ev, e2.GetNode(n.ID)) {
		t.Fatal("旧格式 node:<数字> 条目应仍可命中")
	}
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}
