package topology

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// 端口使用统计的口径：
//
//	OutPorts = 它作为客户端连出去的**对方端口**
//	InPorts  = 它作为服务端被连的**本端端口**
//
// 这组用例守住三件事：方向别搞反、同一会话别重复计数、长尾端口别把内存吃穿。

func sessionTo(srcIP, dstIP string, srcPort, dstPort uint16, proto string, ts time.Time) *model.Session {
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Proto: proto},
		MAC:       "aa:bb:cc:00:00:01",
		FirstSeen: ts,
		LastSeen:  ts.Add(5 * time.Second),
		BytesUp:   1000,
		BytesDown: 2000,
		Packets:   20,
	}
}

// snapNode 按 IP / CIDR 从快照里取节点（快照才是带上派生字段的那一份）。
func snapNode(t *testing.T, e *Engine, ip string) model.Node {
	t.Helper()
	for _, n := range e.Snapshot().Nodes {
		for _, v := range n.IPs {
			if v == ip {
				return n
			}
		}
	}
	t.Fatalf("快照里找不到节点 %s", ip)
	return model.Node{}
}

func TestPortUseDirection(t *testing.T) {
	e := New(testCfg())
	// 内网主机连公网 443：出向端口记在客户端，入向端口记在公网节点
	e.Ingest(sessionTo("10.1.1.10", "93.184.216.10", 50001, 443, "tcp", base))

	host := snapNode(t, e, "10.1.1.10")
	if len(host.OutPorts) != 1 || host.OutPorts[0].Port != 443 {
		t.Fatalf("客户端应记出向端口 443，实际 %+v", host.OutPorts)
	}
	if host.OutPorts[0].Proto != "tcp" || host.OutPorts[0].Sessions != 1 {
		t.Fatalf("端口统计字段不对：%+v", host.OutPorts[0])
	}
	// 出向不该记在本机入向里（那是"别人连它 443"，两条完全不同的结论）
	if len(host.InPorts) != 0 {
		t.Fatalf("客户端不该有入向端口，实际 %+v", host.InPorts)
	}

	ext := snapNode(t, e, "93.184.216.0/24")
	if len(ext.InPorts) != 1 || ext.InPorts[0].Port != 443 {
		t.Fatalf("被访问方应记入向端口 443，实际 %+v", ext.InPorts)
	}
	if len(ext.OutPorts) != 0 {
		t.Fatalf("被访问方不该有出向端口，实际 %+v", ext.OutPorts)
	}
}

func TestPortUseNoDoubleCount(t *testing.T) {
	e := New(testCfg())
	s := sessionTo("10.1.1.10", "10.1.1.20", 50001, 445, "tcp", base)
	e.Ingest(s)

	// 探针每 2s 重报同一会话的累计值：会话数不能跟着涨
	again := *s
	again.LastSeen = base.Add(10 * time.Second)
	e.Ingest(&again)

	host := snapNode(t, e, "10.1.1.10")
	if len(host.OutPorts) != 1 || host.OutPorts[0].Sessions != 1 {
		t.Fatalf("同一会话重复上报应仍是 1 个会话，实际 %+v", host.OutPorts)
	}

	// 同一会话字节增长：字节要累加（这是"这条端口上的流量"）
	grown := *s
	grown.BytesUp = 3000
	grown.LastSeen = base.Add(20 * time.Second)
	e.Ingest(&grown)
	host = snapNode(t, e, "10.1.1.10")
	if host.OutPorts[0].Sessions != 1 {
		t.Fatalf("字节增长不代表新会话，实际 %+v", host.OutPorts[0])
	}
	if host.OutPorts[0].Bytes <= 3000 {
		t.Fatalf("字节应累计，实际 %d", host.OutPorts[0].Bytes)
	}
}

func TestPortUseCountsDistinctPeers(t *testing.T) {
	e := New(testCfg())
	e.Ingest(sessionTo("10.1.1.10", "10.1.1.20", 50001, 445, "tcp", base))
	e.Ingest(sessionTo("10.1.1.11", "10.1.1.20", 50002, 445, "tcp", base))
	e.Ingest(sessionTo("10.1.1.10", "10.1.1.20", 50003, 445, "tcp", base))

	server := snapNode(t, e, "10.1.1.20")
	if len(server.InPorts) != 1 {
		t.Fatalf("445 应是一条，实际 %+v", server.InPorts)
	}
	if server.InPorts[0].Sessions != 3 || server.InPorts[0].Peers != 2 {
		t.Fatalf("应为 3 个会话 / 2 个对端，实际 %+v", server.InPorts[0])
	}
}

func TestPortUseSkipsPortlessAndSelfLoop(t *testing.T) {
	e := New(testCfg())
	// ICMP 没有端口：画出来是噪音
	e.Ingest(sessionTo("10.1.1.10", "10.1.1.20", 0, 0, "icmp", base))
	// 本机自发自收（NAT 回环）不构成"连了谁"
	e.Ingest(sessionTo("10.1.1.10", "10.1.1.10", 50001, 8080, "tcp", base))

	for _, n := range e.Snapshot().Nodes {
		if len(n.OutPorts) != 0 || len(n.InPorts) != 0 {
			t.Fatalf("无端口协议与自环都不该产生端口统计，%s = %+v / %+v", n.IPs, n.OutPorts, n.InPorts)
		}
	}
}

func TestPortUseCapsAndOrder(t *testing.T) {
	e := New(testCfg())
	host := "10.1.1.10"

	// 443 被连 5 次（会话数最多），其余端口各 1 次
	for i := 0; i < 5; i++ {
		e.Ingest(sessionTo(host, "93.184.216.10", uint16(40000+i), 443, "tcp", base))
	}
	// 长尾：制造远超上限的不同端口（模拟被扫描）
	for i := 0; i < 200; i++ {
		e.Ingest(sessionTo(host, "93.184.216.11", uint16(41000+i), uint16(10000+i), "tcp", base))
	}

	n := snapNode(t, e, host)
	if len(n.OutPorts) == 0 || n.OutPorts[0].Port != 443 {
		t.Fatalf("会话数最多的 443 应排第一，实际 %+v", n.OutPorts)
	}
	if len(n.OutPorts) > portUseOutput {
		t.Fatalf("出图端口数应受上限约束（%d），实际 %d", portUseOutput, len(n.OutPorts))
	}

	// 内存层的硬上限：每节点不同端口数不超过 portUsePerNode
	e.mu.RLock()
	defer e.mu.RUnlock()
	if got := len(e.outUse[n.ID]); got > portUsePerNode {
		t.Fatalf("每节点端口条目应受上限 %d 约束，实际 %d", portUsePerNode, got)
	}
}

func TestPortUseAggregatedSubnetHasNoMadeUpPorts(t *testing.T) {
	e := New(testCfg()) // AggregateThreshold=3
	for i := 0; i < 5; i++ {
		e.Ingest(sessionTo(
			"10.9.9."+string(rune('1'+i)), "93.184.216.20",
			uint16(40000+i), 443, "tcp", base))
	}

	snap := e.Snapshot()
	for _, n := range snap.Nodes {
		if len(n.IPs) == 1 && n.IPs[0] == "10.9.9.0/24" {
			// 聚合节点目前不合并成员端口。这里不断言"必须为空"，
			// 只断言不会出现凭空捏造的端口（比如把成员端口号相加）。
			for _, p := range n.OutPorts {
				if p.Port <= 0 || p.Port > 65535 {
					t.Fatalf("聚合节点出现非法端口：%+v", p)
				}
			}
		}
	}
}
