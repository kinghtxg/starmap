package topology

import (
	"fmt"
	"testing"

	"starmap/internal/model"
)

// mkXFFSession 构造一条"经代理由真实客户端发起"的会话：
// 五元组里是代理（src），真实客户端只在 XFF 里。
func mkXFFSession(proxyIP, dstIP, clientIP, proxyMAC string, port uint16) *model.Session {
	s := mkSession(proxyIP, dstIP, proxyMAC, port, base)
	s.RealClientIP = clientIP
	s.XFF = []string{clientIP}
	s.ProxyHops = 1
	return s
}

func nodeByIP(t *testing.T, e *Engine, ip string) *model.Node {
	t.Helper()
	n := e.NodeByIP(ip)
	if n == nil {
		t.Fatalf("节点 %s 不存在", ip)
	}
	return n
}

func hasNodeLabel(n *model.Node, l string) bool {
	for _, x := range n.Labels {
		if x == l {
			return true
		}
	}
	return false
}

// TestForwardedCreatesClientNode XFF 还原出的真实客户端要成为独立节点，
// 否则"代理后面几百台设备"在拓扑上完全不存在。
func TestForwardedCreatesClientNode(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkXFFSession("10.0.0.100", "10.0.0.200", "10.0.0.5", "aa:bb:cc:00:10:00", 41000))

	proxy := nodeByIP(t, e, "10.0.0.100")
	if !hasNodeLabel(proxy, LabelXFFProxy) {
		t.Fatalf("转发节点应带 %s 标签，实际 labels=%v", LabelXFFProxy, proxy.Labels)
	}
	client := nodeByIP(t, e, "10.0.0.5")
	if !hasNodeLabel(client, LabelXFFClient) {
		t.Fatalf("XFF 客户端应带 %s 标签，实际 labels=%v", LabelXFFClient, client.Labels)
	}

	// 关系边：客户端 ↔ 代理，协议为 xff（不是观测到的流量）
	clientID, proxyID := APINodeID(client), APINodeID(proxy)
	got := false
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Protocol != ProtoXFF {
			continue
		}
		if (ed.Src == clientID && ed.Dst == proxyID) || (ed.Src == proxyID && ed.Dst == clientID) {
			got = true
		}
	}
	if !got {
		t.Fatalf("应存在客户端(%s)与代理(%s)之间的 xff 关系边", clientID, proxyID)
	}
}

// TestProxiesAggregatesClients 一个代理后面挂多台客户端时要能汇总。
func TestProxiesAggregatesClients(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkXFFSession("10.0.0.100", "10.0.0.200", "10.0.0.8", "aa:bb:cc:00:10:00", 41001))
	e.Ingest(mkXFFSession("10.0.0.100", "10.0.0.200", "10.0.0.5", "aa:bb:cc:00:10:00", 41002))
	e.Ingest(mkXFFSession("10.0.0.100", "10.0.0.200", "10.0.0.9", "aa:bb:cc:00:10:00", 41003))

	list := e.Proxies()
	if len(list) != 1 {
		t.Fatalf("代理数=%d 期望 1: %+v", len(list), list)
	}
	p := list[0]
	if p.Clients != 3 {
		t.Fatalf("背后客户端数=%d 期望 3: %v", p.Clients, p.ClientIPs)
	}
	if len(p.IPs) == 0 || p.IPs[0] != "10.0.0.100" {
		t.Fatalf("代理 IP 不对: %+v", p.IPs)
	}
	// 排序稳定：.5 / .8 / .9
	want := []string{"10.0.0.5", "10.0.0.8", "10.0.0.9"}
	for i := range want {
		if p.ClientIPs[i] != want[i] {
			t.Fatalf("客户端清单=%v 期望 %v", p.ClientIPs, want)
		}
	}
}

// TestForwardedSelfDeclaredSkipped XFF 首跳等于观测源（自报家门）时不建自环，
// 交给检测器判可疑；否则图上会出现一个自己连自己的节点。
func TestForwardedSelfDeclaredSkipped(t *testing.T) {
	e := New(testCfg())
	s := mkSession("10.0.0.100", "10.0.0.200", "aa:bb:cc:00:10:00", 41004, base)
	s.RealClientIP = "10.0.0.100" // 声称来源即自身
	s.XFF = []string{"10.0.0.100"}
	e.Ingest(s)

	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Protocol == ProtoXFF {
			t.Fatal("自报家门不应产生 xff 关系边")
		}
	}
	if len(e.Proxies()) != 0 {
		t.Fatal("自报家门不应被当作代理")
	}
}

// TestForwardedPublicClientIgnored 公网客户端归外网聚合节点，不单独建内网节点。
func TestForwardedPublicClientIgnored(t *testing.T) {
	e := New(testCfg())
	s := mkSession("10.0.0.100", "10.0.0.200", "aa:bb:cc:00:10:00", 41005, base)
	s.RealClientIP = "203.0.113.7"
	s.XFF = []string{"203.0.113.7"}
	e.Ingest(s)

	if n := e.NodeByIP("203.0.113.7"); n != nil {
		t.Fatal("公网客户端不应作为独立节点建出来")
	}
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Protocol == ProtoXFF {
			t.Fatal("公网客户端不应产生 xff 关系边")
		}
	}
}

// TestProxyNotAggregated 转发节点是结构性收口点，聚合掉它等于藏起"背后一片客户端"的入口，
// 因此它必须像风险锚点一样常驻（V1.8）。客户端本身仍按正常规则参与聚合。
func TestProxyNotAggregated(t *testing.T) {
	e := New(testCfg()) // 聚合阈值 3
	for i := 1; i <= 4; i++ {
		e.Ingest(mkSession(fmt.Sprintf("10.9.9.%d", i), "10.9.9.250",
			fmt.Sprintf("aa:bb:cc:09:09:%02x", i), uint16(46000+i), base))
	}
	if !e.IsAggregated("10.9.9.0/24") {
		t.Fatal("10.9.9.0/24 应已聚合")
	}
	proxy := "10.9.9.100"
	e.Ingest(mkXFFSession(proxy, "10.9.9.200", "10.8.8.5", "aa:bb:cc:09:09:99", 46500))

	n := snapshotNode(e, APINodeID(e.NodeByIP(proxy)))
	if n == nil {
		t.Fatal("七层转发节点不应被网段聚合隐藏")
	}
	if n.Anchor {
		t.Fatal("转发节点不是风险锚点，不应置 Anchor（那是风险语义）")
	}
}
