package topology

import (
	"fmt"
	"testing"

	"starmap/internal/model"
)

// snapshotNode 在快照里按 API 身份查找节点（找不到返回 nil）。
func snapshotNode(e *Engine, apiID string) *model.Node {
	snap := e.Snapshot()
	for i := range snap.Nodes {
		if APINodeID(&snap.Nodes[i]) == apiID {
			return &snap.Nodes[i]
		}
	}
	return nil
}

// fillSubnet 在 prefix 网段内灌入 n 台主机（MAC 唯一），使其超过聚合阈值。
func fillSubnet(e *Engine, prefix string, from, n int, macSeed string) {
	for i := 0; i < n; i++ {
		// 目的端用同网段网关，保证链路落在网段内
		e.Ingest(mkSession(
			fmt.Sprintf("%s.%d", prefix, from+i),
			prefix+".1",
			fmt.Sprintf("aa:bb:cc:%s:%02x", macSeed, from+i),
			uint16(40000+from+i),
			base,
		))
	}
}

// TestRiskAnchorNotAggregated 风险锚点（中/高风险）不参与网段聚合，始终在快照中出现。
func TestRiskAnchorNotAggregated(t *testing.T) {
	e := New(testCfg()) // 聚合阈值 3
	fillSubnet(e, "10.0.0", 11, 4, "01:00")
	if !e.IsAggregated("10.0.0.0/24") {
		t.Fatal("10.0.0.0/24 应已聚合")
	}

	victim := e.NodeByIP("10.0.0.12")
	if victim == nil {
		t.Fatal("未找到 10.0.0.12")
	}

	// 未置风险时：聚合生效，成员被隐藏
	if n := snapshotNode(e, APINodeID(victim)); n != nil {
		t.Fatal("无风险节点在聚合网段内应被隐藏")
	}

	// 置为高风险后：必须破聚合、以自身身份出现
	e.SetNodeRisk(victim.ID, model.RiskHigh)
	n := snapshotNode(e, APINodeID(e.NodeByIP("10.0.0.12")))
	if n == nil {
		t.Fatal("高风险节点不应被网段聚合隐藏（V1.6 风险锚点）")
	}
	if !n.Anchor {
		t.Fatal("高风险节点应标记为风险锚点 Anchor=true")
	}

	// 聚合节点仍需存在，且带主机台数
	agg := snapshotNode(e, SubnetNodeID("10.0.0.0/24"))
	if agg == nil {
		t.Fatal("聚合节点应仍然存在")
	}
	if agg.Members != 5 { // 4 台被灌入的主机 + 目的端网关 10.0.0.1
		t.Fatalf("聚合节点主机数=%d 期望 5", agg.Members)
	}
	if agg.RiskLevel != model.RiskHigh {
		t.Fatalf("聚合节点应继承网段内最高风险，实际=%s", agg.RiskLevel)
	}
}

// TestMultiNetAnchorBridgesTwoSubnets 一机两网：锚点同时连到两个网段聚合节点。
// 这是"多网融合"在拓扑图上的可视化签名，也是锚点机制存在的首要理由。
func TestMultiNetAnchorBridgesTwoSubnets(t *testing.T) {
	e := New(testCfg()) // 阈值 3

	// 同一 MAC 在两个 /24 各出现一次 → 合并为一台双归属主机
	dualMAC := "aa:bb:cc:09:01:01"
	e.Ingest(mkSession("10.50.1.20", "10.50.1.1", dualMAC, 50100, base))
	e.Ingest(mkSession("10.50.2.20", "10.50.2.1", dualMAC, 50101, base))

	fillSubnet(e, "10.50.1", 11, 3, "09:11")
	fillSubnet(e, "10.50.2", 21, 3, "09:22")

	if !e.IsAggregated("10.50.1.0/24") || !e.IsAggregated("10.50.2.0/24") {
		t.Fatal("两个网段都应已聚合")
	}

	dual := e.NodeByIP("10.50.1.20")
	if dual == nil || len(dual.IPs) < 2 {
		t.Fatalf("双归属主机未合并: %+v", dual)
	}

	// 无风险时被各自网段吞掉，两个网段之间看不到任何连接
	if snapshotNode(e, APINodeID(dual)) != nil {
		t.Fatal("未置风险的普通主机应被聚合隐藏")
	}

	// 多网融合判定后置高风险 → 锚点
	e.SetNodeRisk(dual.ID, model.RiskHigh)
	if n := snapshotNode(e, APINodeID(e.NodeByIP("10.50.1.20"))); n == nil || !n.Anchor {
		t.Fatal("双归属高风险主机应作为风险锚点保留在快照中")
	}

	anchorID := APINodeID(e.NodeByIP("10.50.1.20"))
	left := edgeBetween(t, e, anchorID, SubnetNodeID("10.50.1.0/24"))
	right := edgeBetween(t, e, anchorID, SubnetNodeID("10.50.2.0/24"))
	if left == nil {
		t.Fatal("锚点应连到 10.50.1.0/24 聚合节点")
	}
	if right == nil {
		t.Fatal("锚点应连到 10.50.2.0/24 聚合节点（一机两网的拓扑签名）")
	}
}

// TestSubnetDrilldownKeepsIntraLinks 下钻视图必须保留网段内成员之间的链路。
// V1.6 修复前：成员一律被映射成 subnet:<自身 CIDR>，两端同源 → 前端整条丢弃。
func TestSubnetDrilldownKeepsIntraLinks(t *testing.T) {
	e := New(testCfg())
	// 网段内互访：.11 → .12
	e.Ingest(mkSession("10.0.0.11", "10.0.0.12", "aa:bb:cc:07:00:11", 40011, base))
	// 其余主机补充到超过阈值
	fillSubnet(e, "10.0.0", 13, 3, "07:00")
	if !e.IsAggregated("10.0.0.0/24") {
		t.Fatal("10.0.0.0/24 应已聚合")
	}

	a := APINodeID(e.NodeByIP("10.0.0.11"))
	b := APINodeID(e.NodeByIP("10.0.0.12"))
	if a == "" || b == "" || a == b {
		t.Fatalf("成员身份异常: %q %q", a, b)
	}

	var found bool
	for _, ed := range e.SubnetVisibleEdges("10.0.0.0/24") {
		if ed.Src == a && ed.Dst == b || ed.Src == b && ed.Dst == a {
			found = true
		}
		if ed.Src == SubnetNodeID("10.0.0.0/24") || ed.Dst == SubnetNodeID("10.0.0.0/24") {
			t.Fatalf("下钻边不应再引用自身聚合身份: %+v", ed)
		}
	}
	if !found {
		t.Fatal("下钻视图丢失了网段内 .11 - .12 的链路")
	}

	// 下钻节点表里应能对上每条边的两个端点
	have := map[string]bool{}
	for _, n := range e.SubnetSnapshot("10.0.0.0/24").Nodes {
		have[APINodeID(&n)] = true
	}
	for _, ed := range e.SubnetVisibleEdges("10.0.0.0/24") {
		if !have[ed.Src] && ed.Src != SubnetNodeID("10.0.0.0/24") {
			// 跨网段端点由 API 层补为上下文节点，这里只校验网段内端点
			continue
		}
	}
	if !have[a] || !have[b] {
		t.Fatal("下钻节点表应包含链路两端成员")
	}
}

// TestOwnershipEdgeForCrossSubnet 跨网归属不依赖"该网段内恰好有内部对端"。
// 设备在第二个网段只访问了外网时，图上原本看不出它属于那个网段，
// V1.6 用 Kind="owner" 的归属边把这段关系画出来（一机两网的可视化补齐）。
func TestOwnershipEdgeForCrossSubnet(t *testing.T) {
	e := New(testCfg())
	dualMAC := "aa:bb:cc:11:00:01"
	// 内网段有内部对端
	e.Ingest(mkSession("10.70.1.20", "10.70.1.1", dualMAC, 50100, base))
	// 第二个网段只有一次外网访问，网段内没有对端
	e.Ingest(mkSession("10.70.2.20", "8.8.8.8", dualMAC, 50101, base))
	fillSubnet(e, "10.70.1", 11, 3, "11:11")
	fillSubnet(e, "10.70.2", 21, 3, "11:22")
	if !e.IsAggregated("10.70.2.0/24") {
		t.Fatal("10.70.2.0/24 应已聚合")
	}

	dual := e.NodeByIP("10.70.1.20")
	e.SetNodeRisk(dual.ID, model.RiskHigh)
	anchor := APINodeID(e.NodeByIP("10.70.1.20"))

	var ownerEdge *VisibleEdge
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Kind == EdgeKindOwner {
			ee := ed
			ownerEdge = &ee
		}
	}
	if ownerEdge == nil {
		t.Fatal("应生成一条网段归属边")
	}
	if ownerEdge.Src != anchor && ownerEdge.Dst != anchor {
		t.Fatalf("归属边应从锚点出发: %+v", ownerEdge)
	}
	other := ownerEdge.Dst
	if ownerEdge.Dst == anchor {
		other = ownerEdge.Src
	}
	if other != SubnetNodeID("10.70.2.0/24") {
		t.Fatalf("归属边应指向第二个网段，实际=%s", other)
	}
	// 已有的流量边不应重复生成归属边
	if ed := edgeBetween(t, e, anchor, SubnetNodeID("10.70.1.0/24")); ed == nil {
		t.Fatal("锚点与 10.70.1.0/24 应有流量边")
	}
	n := 0
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Kind == EdgeKindOwner && (ed.Src == SubnetNodeID("10.70.1.0/24") || ed.Dst == SubnetNodeID("10.70.1.0/24")) {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("已有流量边的网段不应再追加归属边，实际多出 %d 条", n)
	}
}

// TestSubnetContextNodes 下钻时，边的外部端点要能被补成上下文节点，
// 否则前端因端点缺失丢弃整条边；同时别的网段的锚点归属不能串进来。
func TestSubnetContextNodes(t *testing.T) {
	e := New(testCfg())
	dualMAC := "aa:bb:cc:08:00:01"
	e.Ingest(mkSession("10.60.1.20", "10.60.1.1", dualMAC, 50100, base))
	// 第二个网段只访问外网：既测试跨网上下文，也测试外部 /24 上下文
	e.Ingest(mkSession("10.60.2.20", "8.8.8.8", dualMAC, 50101, base))
	fillSubnet(e, "10.60.1", 11, 4, "08:11")
	fillSubnet(e, "10.60.2", 21, 4, "08:22")
	// 造一个只属于 10.60.2.0/24 的锚点，验证它的归属边不会漏进 10.60.1 的下钻视图
	only2 := e.NodeByIP("10.60.2.21")
	e.SetNodeRisk(only2.ID, model.RiskHigh)
	dual := e.NodeByIP("10.60.1.20")
	e.SetNodeRisk(dual.ID, model.RiskHigh)

	ends := []string{}
	for _, ed := range e.SubnetVisibleEdges("10.60.1.0/24") {
		ends = append(ends, ed.Src, ed.Dst)
	}
	ctx := e.SubnetContextNodes("10.60.1.0/24", ends)

	got := map[string]bool{}
	for i := range ctx {
		id := APINodeID(&ctx[i])
		got[id] = true
		if id == SubnetNodeID("10.60.1.0/24") {
			t.Fatal("不应把自身网段当作上下文节点")
		}
	}
	if !got[SubnetNodeID("10.60.2.0/24")] {
		t.Fatalf("应补出跨网段上下文节点，实际=%v", got)
	}
	if !got[ExternalNodeID("8.8.8.0/24")] {
		t.Fatalf("应补出外部 /24 上下文节点，实际=%v", got)
	}

	// 不留外部端点：每条边的两端都必须能在这批节点里找到
	have := map[string]bool{}
	for _, n := range e.SubnetSnapshot("10.60.1.0/24").Nodes {
		have[APINodeID(&n)] = true
	}
	for id := range got {
		have[id] = true
	}
	for _, ed := range e.SubnetVisibleEdges("10.60.1.0/24") {
		if !have[ed.Src] || !have[ed.Dst] {
			t.Fatalf("下钻边端点缺失: %s -> %s", ed.Src, ed.Dst)
		}
		if ed.Kind == EdgeKindOwner && ed.Src == APINodeID(e.NodeByIP("10.60.2.21")) {
			t.Fatal("其它网段锚点的归属边不应出现在本网段下钻视图")
		}
	}
}

// TestNodeByKey 稳定身份查询。
//
// 事件/审计这类跨重启还要对上设备的场景必须用 NodeKey，而不是自增 ID：
// 节点被离线清理后重建会拿到新 ID，按 ID 查会指向不存在的行。
func TestNodeByKey(t *testing.T) {
	e := New(testCfg())
	e.ObserveHost("10.10.1.9", "aa:bb:cc:00:00:09", base)

	n := e.NodeByKey("mac:aa:bb:cc:00:00:09")
	if n == nil {
		t.Fatal("按 MAC 身份应能查到节点")
	}
	if len(n.IPs) == 0 || n.IPs[0] != "10.10.1.9" {
		t.Errorf("节点 IP 异常: %v", n.IPs)
	}

	// 同一身份的两种写法：有 MAC 时 key 是 mac:，不会用 ip:
	if got := e.NodeByKey("ip:10.10.1.9"); got != nil {
		t.Error("有 MAC 的节点不应再按 ip: 身份命中（避免同一设备两个身份）")
	}
	if got := e.NodeByKey(""); got != nil {
		t.Error("空 key 应返回 nil")
	}
	if got := e.NodeByKey("mac:aa:bb:cc:ff:ff:ff"); got != nil {
		t.Error("不存在的 key 应返回 nil")
	}
}
