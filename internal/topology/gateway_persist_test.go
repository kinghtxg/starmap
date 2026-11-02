package topology_test

import (
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// 网关的"出口身份"必须扛得住重启。
//
// 这个用例来自一次真机演示：灌完数据，图上右上角有一台「10.20.1.1 网关/路由器」，
// 它周围的 30 台办公主机按 /24 聚合成一个网段节点，它自己单独站在核心层——
// 正是想要的样子。然后把进程重启一次，同一个库、同一份数据，**它不见了**。
//
// 原因是"谁是网关"这件事只记在内存表 gatewayMAC 里：进程一重启就空，判不出
// 它是网关，于是它作为普通成员被网段聚合吞掉。而重启那一刻恰恰是最需要看图的
// 时候。修法是把这条证据落成节点标签（LabelGateway），可见性与角色都以它为依据。
func TestGatewayIdentitySurvivesRestart(t *testing.T) {
	st := openStoreFile(t)
	gwMAC := "02:00:00:00:fe:01"

	// 办公网 5 台主机 + 网关。阈值压到 3，保证这个 /24 **一定**被聚合——
	// 用默认阈值的话节点太少、根本不聚合，"被网段吞掉"这条路径压根走不到，
	// 用例会变成只验证角色字段，测不出真正的那个坑。
	cfg := testCfg()
	cfg.AggregateThreshold = 3
	newEngine := func() *topology.Engine {
		e := topology.New(cfg)
		if err := e.AttachStore(st); err != nil {
			t.Fatalf("AttachStore: %v", err)
		}
		return e
	}
	e1 := newEngine()
	base := time.Now().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		pc := "10.77.1." + string(rune('1'+i)) + "0"
		mac := "02:00:00:00:11:0" + string(rune('0'+i))
		// 主机用网关当 DNS：网关的内网 IP 作为目的地址出现
		e1.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{SrcIP: pc, DstIP: "10.77.1.1", SrcPort: uint16(40000 + i), DstPort: 53, Proto: "tcp"},
			MAC:       mac, DstMAC: gwMAC,
			FirstSeen: base, LastSeen: base.Add(time.Minute),
			BytesUp: 3000, BytesDown: 6000, Packets: 20,
		})
		// 上公网：目的在内网之外，以太网目的 MAC 就是网关
		e1.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{SrcIP: pc, DstIP: "198.51.100.20", SrcPort: uint16(41000 + i), DstPort: 443, Proto: "tcp"},
			MAC:       mac, DstMAC: gwMAC,
			FirstSeen: base, LastSeen: base.Add(time.Minute),
			BytesUp: 20000, BytesDown: 80000, Packets: 40,
		})
	}
	if err := e1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	before := findMAC(e1.Snapshot(), gwMAC)
	if before == nil {
		t.Fatal("重启前网关就该在图上（归一或聚合保护没生效）")
	}
	if !hasRoleOf(before.Roles, "gateway") {
		t.Fatalf("重启前网关角色不对: %v", before.Roles)
	}

	// 聚合确实发生了：普通主机已被折叠（否则下面那条断言没有意义）
	if !cidrAggregated(e1, "10.77.1.0/24") {
		t.Fatal("这个 /24 应当已被聚合，用例前提不成立")
	}

	// ---- 模拟进程重启：同一份库、不再灌任何流量 ----
	e2 := newEngine()
	after := findMAC(e2.Snapshot(), gwMAC)
	if after == nil {
		t.Fatal("重启后网关从图上消失了：它被网段聚合吞掉——重启那一刻正是最需要看见出口的时候")
	}
	if !hasRoleOf(after.Roles, "gateway") {
		t.Fatalf("重启后网关变回未识别: %v（证据必须随节点落盘，不能只活在内存里）", after.Roles)
	}
	if len(after.IPs) != 1 || after.IPs[0] != "10.77.1.1" {
		t.Fatalf("重启后网关应带着它的内网地址: %v", after.IPs)
	}
}

// cidrAggregated 判断某个网段是否已被折叠成聚合节点。
func cidrAggregated(e *topology.Engine, cidr string) bool {
	for _, n := range e.Snapshot().Nodes {
		if len(n.IPs) == 1 && n.IPs[0] == cidr && n.Members > 0 {
			return true
		}
	}
	return false
}

func findMAC(snap model.TopoSnapshot, mac string) *model.Node {
	for i := range snap.Nodes {
		if snap.Nodes[i].MAC == mac {
			n := snap.Nodes[i]
			return &n
		}
	}
	return nil
}

func hasRoleOf(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
