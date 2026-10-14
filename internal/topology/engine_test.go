package topology

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

func testCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds:       3600,
		AggregateThreshold: 3,
		NoiseBytes:         400,
		NoisePackets:       4,
		NoiseDurationSec:   2,
	}
}

var base = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// mkSession 构造一条正常流量会话（超过降噪阈值）。
func mkSession(srcIP, dstIP, srcMAC string, srcPort uint16, ts time.Time) *model.Session {
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: 443, Proto: "tcp"},
		MAC:       srcMAC,
		FirstSeen: ts,
		LastSeen:  ts.Add(10 * time.Second),
		BytesUp:   2000,
		BytesDown: 5000,
		Packets:   30,
	}
}

func edgeBetween(t *testing.T, e *Engine, a, b string) *VisibleEdge {
	t.Helper()
	for _, ed := range e.SnapshotEdgePairs() {
		if (ed.Src == a && ed.Dst == b) || (ed.Src == b && ed.Dst == a) {
			ee := ed
			return &ee
		}
	}
	return nil
}

func TestGrowth(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSession("192.168.1.10", "192.168.1.20", "aa:bb:cc:00:00:01", 50001, base))

	snap := e.Snapshot()
	if snap.Stats.NodeCount != 2 {
		t.Fatalf("节点数=%d 期望 2", snap.Stats.NodeCount)
	}
	if snap.Stats.EdgeCount != 1 {
		t.Fatalf("边数=%d 期望 1", snap.Stats.EdgeCount)
	}
	n := e.NodeByIP("192.168.1.10")
	if n == nil || !n.Active || n.FirstSeen.IsZero() || n.LastSeen.IsZero() {
		t.Fatalf("节点字段不完整: %+v", n)
	}
	edges := e.SnapshotEdgePairs()
	if len(edges) != 1 || edges[0].Bytes != 7000 || edges[0].Packets != 30 || edges[0].Protocol != "tcp" {
		t.Fatalf("边字段错误: %+v", edges)
	}
}

func TestMACMerge(t *testing.T) {
	e := New(testCfg())
	mac := "aa:bb:cc:00:00:02"
	e.Ingest(mkSession("192.168.1.10", "192.168.1.20", mac, 50001, base))
	e.Ingest(mkSession("192.168.1.11", "192.168.1.20", mac, 50002, base))

	n := e.NodeByIP("192.168.1.10")
	if n == nil || len(n.IPs) != 2 {
		t.Fatalf("同 MAC 多 IP 未合并: %+v", n)
	}
	if e.NodeByIP("192.168.1.11").ID != n.ID {
		t.Fatal("两个 IP 应指向同一节点")
	}
	if e.Snapshot().Stats.NodeCount != 2 {
		t.Fatalf("节点数=%d 期望 2（合并后）", e.Snapshot().Stats.NodeCount)
	}
}

func TestAggregationAndDrilldown(t *testing.T) {
	e := New(testCfg()) // 阈值 3
	// 同 /24 4 个内网节点（>3 触发聚合）
	for i := 1; i <= 4; i++ {
		e.Ingest(mkSession(fmt.Sprintf("10.0.0.%d", i), "192.168.1.20", fmt.Sprintf("aa:bb:cc:00:01:%02x", i), uint16(51000+i), base))
	}
	if !e.IsAggregated("10.0.0.0/24") {
		t.Fatal("10.0.0.0/24 应已聚合")
	}
	snap := e.Snapshot()
	foundAgg := false
	for _, n := range snap.Nodes {
		if APINodeID(&n) == "subnet:10.0.0.0/24" {
			foundAgg = true
		}
		if len(n.IPs) == 1 && n.IPs[0] == "10.0.0.1" {
			t.Fatal("聚合后成员节点不应出现在快照")
		}
	}
	if !foundAgg {
		t.Fatal("快照应包含 subnet:10.0.0.0/24 聚合节点")
	}
	// 聚合后边应指向聚合节点身份
	if ed := edgeBetween(t, e, "subnet:10.0.0.0/24", APINodeID(e.NodeByIP("192.168.1.20"))); ed == nil {
		t.Fatal("聚合节点与对端之间应有边")
	}
	// 下钻
	sub := e.SubnetSnapshot("10.0.0.0/24")
	if len(sub.Nodes) != 4 {
		t.Fatalf("下钻成员数=%d 期望 4", len(sub.Nodes))
	}
	if len(e.SubnetVisibleEdges("10.0.0.0/24")) == 0 {
		t.Fatal("下钻应返回成员相关边")
	}
}

func TestAggregationHysteresis(t *testing.T) {
	e := New(testCfg())
	for i := 1; i <= 4; i++ {
		e.Ingest(mkSession(fmt.Sprintf("10.0.0.%d", i), "192.168.1.20", fmt.Sprintf("aa:bb:cc:00:02:%02x", i), uint16(52000+i), base))
	}
	// §10.10：阈值上调不拆分
	e.UpdateConfig(model.SystemConfig{AgingSeconds: 3600, AggregateThreshold: 100, NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2})
	if !e.IsAggregated("10.0.0.0/24") {
		t.Fatal("上调阈值不应拆分已聚合节点（迟滞）")
	}
	// 新网段 2 节点不聚合
	e.Ingest(mkSession("10.0.1.1", "192.168.1.20", "aa:bb:cc:00:03:01", 53001, base))
	e.Ingest(mkSession("10.0.1.2", "192.168.1.20", "aa:bb:cc:00:03:02", 53002, base))
	if e.IsAggregated("10.0.1.0/24") {
		t.Fatal("2 节点未超阈值 100，不应聚合")
	}
	// §10.10：阈值下调立即重聚合
	e.UpdateConfig(model.SystemConfig{AgingSeconds: 3600, AggregateThreshold: 1, NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2})
	if !e.IsAggregated("10.0.1.0/24") {
		t.Fatal("下调阈值应立即重聚合")
	}
}

func TestNoiseFilter(t *testing.T) {
	e := New(testCfg())
	// 三条件同时满足：bytes<400 AND duration<2s AND packets<4 → 不建边
	noise := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", SrcPort: 54001, DstPort: 80, Proto: "tcp"},
		FirstSeen: base, LastSeen: base.Add(time.Second),
		BytesUp: 100, BytesDown: 100, Packets: 2,
	}
	e.Ingest(noise)
	if e.Snapshot().Stats.EdgeCount != 0 {
		t.Fatal("降噪会话不应建边")
	}
	// 任一条件不满足即建边（包数够）
	ok := mkSession("192.168.1.10", "192.168.1.20", "aa:bb:cc:00:04:01", 54002, base)
	ok.BytesUp, ok.BytesDown = 100, 100 // 字节仍低，但包数 30
	e.Ingest(ok)
	if e.Snapshot().Stats.EdgeCount != 1 {
		t.Fatal("包数超过阈值应建边")
	}
}

func TestAging(t *testing.T) {
	e := New(testCfg()) // aging 3600s
	e.Ingest(mkSession("192.168.1.10", "192.168.1.20", "aa:bb:cc:00:05:01", 55001, base))
	e.Age(base.Add(30 * time.Minute))
	if !e.SnapshotEdgePairs()[0].Active {
		t.Fatal("未超老化时长的边应保持 Active")
	}
	e.Age(base.Add(2 * time.Hour))
	edges := e.SnapshotEdgePairs()
	if len(edges) != 1 || edges[0].Active {
		t.Fatal("超老化时长应置灰 Active=false")
	}
	snap := e.Snapshot()
	if snap.Stats.ActiveEdges != 0 || snap.Stats.ActiveNodes != 0 {
		t.Fatalf("老化后活跃统计应为 0: %+v", snap.Stats)
	}
}

func TestNATRepair(t *testing.T) {
	e := New(testCfg())
	mac := "aa:bb:cc:00:06:01"
	// 内网节点
	e.Ingest(mkSession("192.168.1.10", "192.168.1.20", mac, 56001, base))
	internalID := e.NodeByIP("192.168.1.10").ID
	// NAT 场景：同 MAC 的会话源变成公网 IP → 链路应指向真实源节点
	natted := mkSession("203.0.113.9", "192.168.1.20", mac, 56002, base)
	e.Ingest(natted)
	if got := e.NodeByIP("192.168.1.10").ID; got != internalID {
		t.Fatal("节点 ID 不应变化")
	}
	// 公网源 IP 不应单独聚合建边
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Src == "ext:203.0.113.0/24" || ed.Dst == "ext:203.0.113.0/24" {
			t.Fatal("NAT 后公网地址不应建边")
		}
	}
}

func TestExternalAggregation(t *testing.T) {
	e := New(testCfg())
	// 两个同 /24 公网 IP → 一个外部聚合节点
	e.Ingest(mkSession("192.168.1.10", "8.8.8.8", "aa:bb:cc:00:07:01", 57001, base))
	e.Ingest(mkSession("192.168.1.10", "8.8.8.10", "aa:bb:cc:00:07:01", 57002, base))
	snap := e.Snapshot()
	extCount := 0
	for _, n := range snap.Nodes {
		if APINodeID(&n) == "ext:8.8.8.0/24" {
			extCount++
		}
	}
	if extCount != 1 {
		t.Fatalf("同 /24 公网应聚合为 1 个外部节点，实际 %d", extCount)
	}
	// 内部节点 1 + 外部聚合 1 = 2
	if snap.Stats.NodeCount != 2 {
		t.Fatalf("节点数=%d 期望 2", snap.Stats.NodeCount)
	}
}

func TestIdempotentIngest(t *testing.T) {
	e := New(testCfg())
	s := mkSession("192.168.1.10", "192.168.1.20", "aa:bb:cc:00:08:01", 58001, base)
	e.Ingest(s)
	e.Ingest(s) // 重复摄入同一会话
	edges := e.SnapshotEdgePairs()
	if len(edges) != 1 || edges[0].Bytes != 7000 {
		t.Fatalf("重复摄入不应重复累计: %+v", edges[0])
	}
	// 增量摄入：字节增长
	s.BytesUp += 1000
	e.Ingest(s)
	if e.SnapshotEdgePairs()[0].Bytes != 8000 {
		t.Fatalf("增量累计错误: %+v", e.SnapshotEdgePairs()[0])
	}
}

func TestDomainAssign(t *testing.T) {
	e := New(testCfg())
	e.SetDomains([]model.NetDomain{
		{Name: "gov", CIDRs: []string{"10.0.0.0/8"}},
		{Name: "prod", CIDRs: []string{"192.168.0.0/16"}},
	})
	e.Ingest(mkSession("10.1.2.3", "192.168.1.20", "aa:bb:cc:00:09:01", 59001, base))
	if n := e.NodeByIP("10.1.2.3"); n.Domain != "gov" {
		t.Fatalf("Domain=%q 期望 gov", n.Domain)
	}
	// 域变更后重算
	e.SetDomains([]model.NetDomain{{Name: "office", CIDRs: []string{"10.0.0.0/8"}}})
	if n := e.NodeByIP("10.1.2.3"); n.Domain != "office" {
		t.Fatalf("域更新后 Domain=%q 期望 office", n.Domain)
	}
}

func TestObserveHostProbe(t *testing.T) {
	e := New(testCfg())
	id := e.ObserveHost("192.168.9.9", "aa:bb:cc:09:09:09", base)
	n := e.GetNode(id)
	if n == nil || !n.Active {
		t.Fatal("探测注入应创建激活节点")
	}
	found := false
	for _, l := range n.Labels {
		if l == LabelProbe {
			found = true
		}
	}
	if !found {
		t.Fatal("探测节点应带 probe 标签")
	}
}
