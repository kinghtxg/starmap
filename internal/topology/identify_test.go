package topology

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// mkSvc 构造一条"某主机访问某端口"的会话（用于身份识别测试）。
func mkSvc(srcIP, dstIP, srcMAC string, srcPort, dstPort uint16, ts time.Time) *model.Session {
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Proto: "tcp"},
		MAC:       srcMAC,
		FirstSeen: ts,
		LastSeen:  ts.Add(10 * time.Second),
		BytesUp:   2000,
		BytesDown: 5000,
		Packets:   30,
	}
}

// nodeByIP 在快照里按 IP 找节点（快照是副本，不能拿 NodeByIP）。
func snapNodeByIP(snap model.TopoSnapshot, ip string) *model.Node {
	for i := range snap.Nodes {
		for _, x := range snap.Nodes[i].IPs {
			if x == ip {
				return &snap.Nodes[i]
			}
		}
	}
	return nil
}

func hasRole(n *model.Node, role string) bool {
	for _, r := range n.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func hasPort(n *model.Node, port int) bool {
	for _, p := range n.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// 存储设备：被别的机器访问文件共享 / DSM 管理口 → NAS。
func TestIdentifyNAS(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSvc("192.168.31.59", "192.168.31.20", "aa:bb:cc:00:00:59", 50001, 445, base))
	e.Ingest(mkSvc("192.168.31.60", "192.168.31.20", "aa:bb:cc:00:00:60", 50002, 5000, base))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.20")
	if n == nil {
		t.Fatal("未找到 192.168.31.20")
	}
	if !hasRole(n, RoleNAS) {
		t.Fatalf("应识别为 NAS，实际 roles=%v services=%v", n.Roles, n.Services)
	}
	if n.Role != RoleNAS {
		t.Fatalf("主角色应为 nas，实际 %q", n.Role)
	}
	if !hasPort(n, 445) || !hasPort(n, 5000) {
		t.Fatalf("应记录 445/5000 端口，实际 %v", n.Ports)
	}
	if n.InboundPeers != 2 {
		t.Fatalf("入向对端应为 2，实际 %d", n.InboundPeers)
	}
}

// 关键回归：本机发 DNS 查询 ≠ 它是 DNS 服务器。
//
// 这正是用户第一次看真实拓扑时提出的疑问——"31.20 是 NAS，但是好像也有 DNS"。
// 那台 NAS 只是在给自己解析域名（大量 UDP 53 出向），它不是 DNS 服务器。
// 如果按"出现过 53 端口"判角色，全网每台机器都会变成 DNS 服务器。
func TestIdentifyDNSClientIsNotServer(t *testing.T) {
	e := New(testCfg())
	// NAS 作为客户端向公共 DNS 查询（大量出向 53）
	for i := 0; i < 5; i++ {
		e.Ingest(mkSvc("192.168.31.20", "114.114.114.114", "f0:2f:74:2e:d9:b3", uint16(50010+i), 53, base))
	}
	n := snapNodeByIP(e.Snapshot(), "192.168.31.20")
	if n == nil {
		t.Fatal("未找到 192.168.31.20")
	}
	if hasRole(n, RoleDNS) {
		t.Fatalf("出向 DNS 查询不应识别为 DNS 服务器，roles=%v", n.Roles)
	}
	if hasPort(n, 53) {
		t.Fatalf("出向 53 不应记入服务端口，ports=%v", n.Ports)
	}
}

// 真正的 DNS 服务器：别人来问它。
func TestIdentifyDNSServer(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSvc("192.168.31.59", "192.168.31.1", "aa:bb:cc:00:00:59", 50020, 53, base))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.1")
	if n == nil || !hasRole(n, RoleDNS) {
		t.Fatalf("被访问 53 端口应识别为 DNS 服务器，实际 %+v", n)
	}
}

// 仅 445、且只有一台机器来连 → 不足以判 NAS（办公电脑默认也开 445）。
func TestIdentifySMBWithSinglePeerNotNAS(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSvc("192.168.31.59", "192.168.31.61", "aa:bb:cc:00:00:59", 50030, 445, base))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.61")
	if n == nil {
		t.Fatal("未找到 192.168.31.61")
	}
	if hasRole(n, RoleNAS) {
		t.Fatalf("单对端 445 不应判为 NAS，roles=%v", n.Roles)
	}
}

// 网关/路由器：有主机的公网流量把它的 MAC 当首跳出口。
func TestIdentifyGateway(t *testing.T) {
	const routerMAC = "50:4f:3b:2a:23:00"
	e := New(testCfg())
	// 路由器自身有流量，节点因此带上 MAC
	e.Ingest(mkSvc("192.168.31.1", "192.168.31.20", routerMAC, 50040, 80, base))
	// 终端访问公网，首跳 MAC 是路由器
	s := mkSession("192.168.31.20", "8.8.8.8", "f0:2f:74:2e:d9:b3", 50041, base)
	s.DstMAC = routerMAC
	e.Ingest(s)

	n := snapNodeByIP(e.Snapshot(), "192.168.31.1")
	if n == nil {
		t.Fatal("未找到 192.168.31.1")
	}
	if !hasRole(n, RoleGateway) {
		t.Fatalf("被当作首跳出口应识别为网关，roles=%v gateway_for=%d", n.Roles, n.GatewayFor)
	}
	if n.GatewayFor != 1 {
		t.Fatalf("GatewayFor 应为 1，实际 %d", n.GatewayFor)
	}
}

// 没有任何入向服务的节点是终端，不是服务器。
func TestIdentifyTerminal(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSession("192.168.31.59", "8.8.8.8", "aa:bb:cc:00:00:59", 50050, base))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.59")
	if n == nil {
		t.Fatal("未找到 192.168.31.59")
	}
	if n.Role != RoleHost {
		t.Fatalf("无入向服务应为 host，实际 %q roles=%v services=%v", n.Role, n.Roles, n.Services)
	}
}

// 公网聚合节点角色为 external。
func TestIdentifyExternalNode(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkSession("192.168.31.59", "8.8.8.8", "aa:bb:cc:00:00:59", 50060, base))

	var ext *model.Node
	for i := range e.Snapshot().Nodes {
		n := e.Snapshot().Nodes[i]
		if hasLabel(&n, LabelExternalAg) {
			ext = &n
			break
		}
	}
	if ext == nil {
		t.Skip("本用例下未生成外部聚合节点")
	}
	if ext.Role != RoleExternal {
		t.Fatalf("外部节点角色应为 external，实际 %q", ext.Role)
	}
}

// 网关节点要被显式建出来，并连一条"出网路径"边。
//
// 网关在被动侧只以 MAC 出现（公网流量的首跳下一跳），IP 永远看不到。
// 过去它是因为整天发 mDNS 才"顺带"进了图；把多播噪音过滤掉之后，
// 路由器就直接从图上消失了——这比误报更糟：不是多了一个错的东西，
// 而是少了一个最该看见的东西。
func TestGatewayNodeMaterialized(t *testing.T) {
	const routerMAC = "50:4f:3b:2a:23:00"
	e := New(testCfg())
	s := mkSession("192.168.31.20", "8.8.8.8", "f0:2f:74:2e:d9:b3", 50080, base)
	s.DstMAC = routerMAC
	e.Ingest(s)

	snap := e.Snapshot()
	var gw *model.Node
	for i := range snap.Nodes {
		if snap.Nodes[i].MAC == routerMAC {
			gw = &snap.Nodes[i]
			break
		}
	}
	if gw == nil {
		t.Fatal("应为首跳网关 MAC 建立节点")
	}
	if len(gw.IPs) != 0 {
		t.Fatalf("网关节点不该凭空有 IP，实际 %v", gw.IPs)
	}
	if !hasRole(gw, RoleGateway) {
		t.Fatalf("网关节点应判定为 gateway，实际 roles=%v", gw.Roles)
	}

	found := false
	for _, ed := range e.SnapshotEdgePairs() {
		if ed.Kind == EdgeKindGateway {
			found = true
		}
	}
	if !found {
		t.Fatal("应生成 kind=gateway 的出网路径边")
	}
}

// 广播 MAC 不是设备，不能建成网关节点。
func TestBroadcastMACNotGateway(t *testing.T) {
	e := New(testCfg())
	s := mkSession("192.168.31.20", "8.8.8.8", "f0:2f:74:2e:d9:b3", 50081, base)
	s.DstMAC = "ff:ff:ff:ff:ff:ff"
	e.Ingest(s)
	for _, n := range e.Snapshot().Nodes {
		if n.MAC == "ff:ff:ff:ff:ff:ff" {
			t.Fatal("广播 MAC 不应成为节点")
		}
	}
}

// 没有任何正面证据时不下结论。
//
// 这条约束来自真实故障：端口/对端证据只存在内存里滚，进程重启后归零。此时若还
// 按默认值硬判一个 host，就等于把一台正在对外提供 DNS 服务的机器标成"普通终端"——
// 用户照这个结论排查会直接走错方向。宁可显示"未识别"。
func TestIdentifyNoEvidenceNoRole(t *testing.T) {
	e := New(testCfg())
	// 一条与任何已知服务无关的会话：目的端口 9999 不在服务目录，且 192.168.31.61
	// 从未作为源出现过（不是本机主动发起），因此它既没有服务端口证据，也没有终端证据。
	e.Ingest(mkSvc("192.168.31.59", "192.168.31.61", "aa:bb:cc:00:00:59", 50090, 9999, base))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.61")
	if n == nil {
		t.Fatal("未找到 192.168.31.61")
	}
	if len(n.Roles) != 0 || n.Role != "" {
		t.Fatalf("无正面证据时不应给角色，实际 role=%q roles=%v", n.Role, n.Roles)
	}
}

func TestIdentifyMultiRole(t *testing.T) {
	const routerMAC = "50:4f:3b:2a:23:00"
	e := New(testCfg())
	e.Ingest(mkSvc("192.168.31.59", "192.168.31.1", "aa:bb:cc:00:00:59", 50070, 53, base))
	e.Ingest(mkSvc("192.168.31.1", "192.168.31.20", routerMAC, 50071, 80, base))
	s := mkSession("192.168.31.20", "8.8.8.8", "f0:2f:74:2e:d9:b3", 50072, base)
	s.DstMAC = routerMAC
	e.Ingest(s)

	n := snapNodeByIP(e.Snapshot(), "192.168.31.1")
	if n == nil {
		t.Fatal("未找到 192.168.31.1")
	}
	if !hasRole(n, RoleGateway) || !hasRole(n, RoleDNS) {
		t.Fatalf("应同时具备 gateway 与 dns 角色，实际 roles=%v", n.Roles)
	}
	if n.Role != RoleGateway {
		t.Fatalf("主角色应为 gateway（更具体），实际 %q", n.Role)
	}
}
