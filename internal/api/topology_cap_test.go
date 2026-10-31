// 拓扑快照安全阀的契约测试（V1.5.2）。
//
// 起因是一次真实压测：检测规则在"客户端与服务器分属两个域"的网络形态下会对
// 几乎每台主机命中多网融合（这是验收标准 4.8 的既定语义），而中高风险节点
// 按设计不参与 /24 聚合，于是节点数从几百个聚合节点涨到 7.4 万个主机节点，
// /api/topology 返回 67 MB、耗时 24.8 秒，浏览器直接卡死。
//
// 本文件守住三件事：
//  1. 节点/边数量有硬上限；
//  2. 截断必须显式（Truncated + 真实总数），不能被误读成全景；
//  3. 截断后不得出现指向不存在节点的悬空边。
package api

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestTopologySnapshotTruncates 节点数超过上限时截断，并如实报告总数。
func TestTopologySnapshotTruncates(t *testing.T) {
	cfg := testCfg()
	cfg.AggregateThreshold = 1 << 20 // 关掉聚合：本用例要造"大量独立主机"
	h, _ := newTestRouter(t, cfg)

	const n = maxTopologyNodes + 800
	flows := make([]map[string]any, 0, n)
	for i := 1; i <= n; i++ {
		// 每个 /24 只放少量主机，避免触发聚合；同时保证 IP 互不相同
		flows = append(flows, map[string]any{
			"src_ip":   fmt.Sprintf("10.%d.%d.%d", 40+(i>>16)&0xff, (i>>8)&0xff, i&0xff),
			"dst_ip":   "172.16.9.9",
			"src_port": 20000 + i%40000,
			"dst_port": 443, "proto": "tcp",
			"mac":      fmt.Sprintf("02:aa:%02x:%02x:%02x:01", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			"bytes_up": 1000, "bytes_down": 2000, "packets": 5,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(time.Minute).Format(time.RFC3339),
		})
	}
	w := doReq(t, h, "POST", "/api/ingest/probe", map[string]any{
		"probe_id": "many", "sent_at": base.Format(time.RFC3339), "flows": flows,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("播种失败 %d: %s", w.Code, w.Body.String())
	}

	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/topology = %d", w.Code)
	}
	m := decodeObject(t, w.Body.Bytes())

	nodes, _ := m["Nodes"].([]any)
	edges, _ := m["Edges"].([]any)
	if len(nodes) > maxTopologyNodes {
		t.Fatalf("节点数 %d 超过上限 %d，安全阀没生效", len(nodes), maxTopologyNodes)
	}
	if len(edges) > maxTopologyEdges {
		t.Fatalf("边数 %d 超过上限 %d", len(edges), maxTopologyEdges)
	}
	if tr, ok := m["Truncated"].(bool); !ok || !tr {
		t.Fatalf("截断必须显式声明，实际 Truncated=%v", m["Truncated"])
	}
	total, _ := m["TotalNodes"].(float64)
	if int(total) <= len(nodes) {
		t.Fatalf("TotalNodes 应是截断前的真实总数 %d，实际 %v（等于返回条数就说明没报真数）",
			n, m["TotalNodes"])
	}

	// 截断后不允许悬空边：前端会照 SrcID/DstID 连直线，指向不存在的节点就是断头路。
	ids := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if obj, ok := n.(map[string]any); ok {
			if id, ok := obj["ID"].(string); ok {
				ids[id] = true
			}
		}
	}
	for _, e := range edges {
		obj, ok := e.(map[string]any)
		if !ok {
			continue
		}
		src, _ := obj["SrcID"].(string)
		dst, _ := obj["DstID"].(string)
		if !ids[src] || !ids[dst] {
			t.Fatalf("悬空边 %s->%s：端点不在返回的节点集合里", src, dst)
		}
	}
}

// TestTopologySnapshotNotTruncatedWhenSmall 正常规模下不得误报截断。
func TestTopologySnapshotNotTruncatedWhenSmall(t *testing.T) {
	h := seedHosts(t, "10.20.5.1", "10.20.5.2")
	w := doReq(t, h, "GET", "/api/topology", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/topology = %d", w.Code)
	}
	m := decodeObject(t, w.Body.Bytes())
	if tr, _ := m["Truncated"].(bool); tr {
		t.Fatal("小规模拓扑不应被截断")
	}
	nodes, _ := m["Nodes"].([]any)
	total, _ := m["TotalNodes"].(float64)
	if int(total) != len(nodes) {
		t.Fatalf("未截断时 TotalNodes 应等于节点数：%v vs %d", m["TotalNodes"], len(nodes))
	}
}

// TestCapTopologyNodesKeepsGroups 截断时必须先保住聚合节点——它们是"网段全貌"。
func TestCapTopologyNodesKeepsGroups(t *testing.T) {
	nodes := make([]model.Node, 0, 10)
	for i := 0; i < 3; i++ {
		nodes = append(nodes, model.Node{ID: int64(1000 + i), Members: 50, RiskLevel: "none"})
	}
	for i := 0; i < 10; i++ {
		nodes = append(nodes, model.Node{ID: int64(i + 1), RiskLevel: "none"})
	}
	got := capTopologyNodes(nodes, 5)
	if len(got) != 5 {
		t.Fatalf("应返回 5 个节点，实际 %d", len(got))
	}
	groups := 0
	for _, n := range got {
		if n.Members > 0 {
			groups++
		}
	}
	if groups != 3 {
		t.Fatalf("3 个聚合节点都应保留，实际保留 %d 个", groups)
	}
}

// TestCapTopologyNodesPrefersRisk 名额有限时优先保留高风险节点。
func TestCapTopologyNodesPrefersRisk(t *testing.T) {
	nodes := []model.Node{
		{ID: 1, RiskLevel: "none"},
		{ID: 2, RiskLevel: "high"},
		{ID: 3, RiskLevel: "mid"},
		{ID: 4, RiskLevel: "none"},
	}
	got := capTopologyNodes(nodes, 2)
	if len(got) != 2 {
		t.Fatalf("应返回 2 个节点，实际 %d", len(got))
	}
	seen := map[int64]bool{}
	for _, n := range got {
		seen[n.ID] = true
	}
	if !seen[2] || !seen[3] {
		t.Fatalf("应优先保留 high/mid 节点，实际 %v", seen)
	}
}
