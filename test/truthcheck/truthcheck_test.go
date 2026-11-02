package truthcheck_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"starmap/internal/simnet"
	"starmap/test/truthcheck"
)

// 校验器自己的测试。
//
// 为什么必须写：一套"永远绿"的断言比没有断言更糟——它让人相信已经测过了。
// 这里的做法是**变异测试**：先造一个完美引擎（用真值直接生成应有的图），
// 确认校验器放行；再把图逐项弄坏（字节翻倍、拆节点、并节点、删边、丢端口），
// 确认每一项都真的会红。
//
// 如果哪天有人把某条断言写软了（比如把 >1.02 改成 >1.5），对应的变异用例
// 立刻失败——这就是判据本身的回归测试。

// sink 把真值直接翻译成"完美引擎应该产出的图"。
//
// 关键点：它只用观测（Sessions）和真机清单，不复刻任何引擎算法。
// 节点键用独立的 nX 命名空间，顺带验证 Key 与边端点在同一命名空间这个约定。
type sink struct {
	nodes []truthcheck.Node
	edges []truthcheck.Edge
	// ip → 节点键
	owner map[string]string
}

func perfect(w *simnet.World) *sink {
	s := &sink{owner: map[string]string{}}
	sessions := w.Sessions()

	seenIP := map[string]bool{}
	// 只有 XFF 里才知道的客户端：被动侧看不到它的直连流量，但一个"完美引擎"
	// 必须把它还原出来，否则代理背后那一大片终端在图上不存在。
	viaXFF := map[string]string{} // 客户端 IP → 代理 IP
	for _, sess := range sessions {
		seenIP[sess.FiveTuple.SrcIP] = true
		seenIP[sess.FiveTuple.DstIP] = true
		if sess.RealClientIP != "" {
			viaXFF[sess.RealClientIP] = sess.FiveTuple.SrcIP
		}
	}

	idx := 0
	for i := range w.Hosts {
		h := &w.Hosts[i]
		any := false
		for _, ip := range h.IPs {
			if seenIP[ip] {
				any = true
			}
		}
		if _, ok := viaXFF[h.IPs[0]]; ok && len(h.IPs) > 0 {
			any = true
		}
		if !any {
			continue
		}
		idx++
		key := fmt.Sprintf("n%d", idx)
		n := truthcheck.Node{
			Key: key, NodeKey: "mac:" + h.MAC, IPs: h.IPs, MAC: h.MAC,
			FirstSeen: w.StartAt, Roles: h.Roles, Labels: h.Labels, Members: 1,
		}
		for _, ip := range h.IPs {
			s.owner[ip] = key
		}
		s.nodes = append(s.nodes, n)
	}
	// XFF 还原出的关系边：客户端 → 代理（无字节，不是观测到的流量而是还原出的路径）
	for clientIP, proxyIP := range viaXFF {
		ck, pk := s.owner[clientIP], s.owner[proxyIP]
		if ck == "" || pk == "" || ck == pk {
			continue
		}
		s.edges = append(s.edges, truthcheck.Edge{Src: ck, Dst: pk, Kind: "xff", FirstSeen: w.StartAt})
	}

	// 端口与边都从观测来（理想情况：看见什么记什么）
	//
	// 但必须先按**会话**去重：两个探针看到同一条会话时，报的是同一个五元组的
	// 两份重复快照，字节是累计值而不是两份数据。直接相加就会把"完美的去重"
	// 算成 2 倍——这正是真值校验里最容易自己骗自己的地方。
	port := map[string]map[int]bool{}
	type pair struct {
		a, b string
		key  string
	}
	acc := map[string]int64{}
	var order []pair
	seenSess := map[string]bool{}
	for _, sess := range sessions {
		ft := sess.FiveTuple
		sk := fmt.Sprintf("%s:%d|%s:%d|%s", ft.SrcIP, ft.SrcPort, ft.DstIP, ft.DstPort, ft.Proto)
		if seenSess[sk] {
			continue // 同一会话的又一次快照
		}
		seenSess[sk] = true

		src := s.owner[ft.SrcIP]
		dst := s.owner[ft.DstIP]
		if dst != "" {
			if port[dst] == nil {
				port[dst] = map[int]bool{}
			}
			port[dst][int(ft.DstPort)] = true
		}
		if src == "" || dst == "" || src == dst {
			continue
		}
		k := src + "|" + dst
		if _, ok := acc[k]; !ok {
			order = append(order, pair{src, dst, k})
		}
		acc[k] += sess.BytesUp + sess.BytesDown
	}
	for i := range s.nodes {
		for p := range port[s.nodes[i].Key] {
			s.nodes[i].Ports = append(s.nodes[i].Ports, p)
		}
	}
	for _, p := range order {
		s.edges = append(s.edges, truthcheck.Edge{
			Src: p.a, Dst: p.b, Kind: "traffic", Bytes: acc[p.key], FirstSeen: w.StartAt,
		})
	}
	return s
}

func world(t *testing.T) *simnet.World {
	t.Helper()
	return simnet.Clean(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
}

// TestPerfectGraphPasses 完美引擎必须通过——否则是校验器自己算错。
func TestPerfectGraphPasses(t *testing.T) {
	w := world(t)
	s := perfect(w)
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("完美图被判失败，校验器有问题：\n%s", rep)
	}
	if got := rep.Metrics["字节比"]; got != "1.000" {
		t.Errorf("完美图的字节比应为 1.000，实际 %s", got)
	}
}

// TestByteDoubleCountFails 字节翻倍必须红。
func TestByteDoubleCountFails(t *testing.T) {
	w := world(t)
	s := perfect(w)
	for i := range s.edges {
		s.edges[i].Bytes *= 2
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("字节翻倍没被抓到：\n%s", rep)
	}
}

// TestSplitHostFails 一台设备被拆成两个节点必须红。
func TestSplitHostFails(t *testing.T) {
	w := world(t)
	s := perfect(w)
	// 把第一台设备的第二个 IP 挪到一个新节点上（模拟"按 IP 建节点、没按 MAC 归一"）
	n := &s.nodes[0]
	if len(n.IPs) < 1 {
		t.Skip("该设备只有一个 IP，无法构造拆分")
	}
	orphanKey := "n-orphan"
	ip := n.IPs[0]
	s.owner[ip] = orphanKey
	s.nodes = append(s.nodes, truthcheck.Node{
		Key: orphanKey, NodeKey: "ip:" + ip, IPs: []string{ip}, FirstSeen: w.StartAt,
	})
	// 这里必须同时改边端点，否则测的只是"边不全"而不是"被拆"
	for i := range s.edges {
		if s.edges[i].Src == n.Key {
			s.edges[i].Src = orphanKey
		}
		if s.edges[i].Dst == n.Key {
			s.edges[i].Dst = orphanKey
		}
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("拆开设备没被抓到：\n%s", rep)
	}
}

// TestMergedHostsFail 两台设备被并成一个节点必须红（反向：少设备）。
func TestMergedHostsFail(t *testing.T) {
	w := world(t)
	s := perfect(w)
	if len(s.nodes) < 2 {
		t.Fatal("场景至少要有两台设备")
	}
	a, b := s.nodes[0], s.nodes[1]
	// 把 b 的 IP 全塞进 a，并删掉 b，边端点重指向 a
	for _, ip := range b.IPs {
		a.IPs = append(a.IPs, ip)
		s.owner[ip] = a.Key
	}
	s.nodes = s.nodes[1:]
	for i := range s.edges {
		if s.edges[i].Src == b.Key {
			s.edges[i].Src = a.Key
		}
		if s.edges[i].Dst == b.Key {
			s.edges[i].Dst = a.Key
		}
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("两台设备被并成一个节点没被抓到：\n%s", rep)
	}
}

// TestDuplicateIPFails 同一 IP 落在两个节点上必须红。
func TestDuplicateIPFails(t *testing.T) {
	w := world(t)
	s := perfect(w)
	ip := s.nodes[0].IPs[0]
	s.nodes = append(s.nodes, truthcheck.Node{
		Key: "n-dup", NodeKey: "ip:" + ip, IPs: []string{ip}, FirstSeen: w.StartAt,
	})
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("IP 重复归属没被抓到：\n%s", rep)
	}
}

// TestMissingEdgeFails 删一条边必须红。
func TestMissingEdgeFails(t *testing.T) {
	w := world(t)
	s := perfect(w)
	if len(s.edges) == 0 {
		t.Fatal("场景没有边")
	}
	s.edges = s.edges[1:]
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("缺边没被抓到：\n%s", rep)
	}
}

// TestMissingPortFails 观测到的端口没进节点画像必须红。
func TestMissingPortFails(t *testing.T) {
	w := world(t)
	s := perfect(w)
	found := false
	for i := range s.nodes {
		if len(s.nodes[i].Ports) > 0 {
			s.nodes[i].Ports = s.nodes[i].Ports[1:]
			found = true
			break
		}
	}
	if !found {
		t.Fatal("没有节点带端口，场景构造有问题")
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("端口漏识没被抓到：\n%s", rep)
	}
}

// TestGhostNodeIsSoftOnly 多出来的节点只算提示，不阻断。
// 网关推断、XFF 派生都会合法地产生额外节点，判成硬失败会逼人关掉断言。
func TestGhostNodeIsSoftOnly(t *testing.T) {
	w := world(t)
	s := perfect(w)
	s.nodes = append(s.nodes, truthcheck.Node{
		Key: "n-ghost", NodeKey: "ip:203.0.113.9", IPs: []string{"203.0.113.9"}, FirstSeen: w.StartAt,
	})
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("幽灵节点不该是硬失败：\n%s", rep)
	}
	if len(rep.Soft) == 0 {
		t.Fatalf("幽灵节点连提示都没给：\n%s", rep)
	}
}

// TestNATRatioWithinLimitIsSoft NAT 场景的 2 倍是上限不是缺陷：只提示，且必须提示。
func TestNATRatioWithinLimitIsSoft(t *testing.T) {
	w := simnet.NAT(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	s := perfect(w)
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("NAT 场景的已知重复不该判硬失败：\n%s", rep)
	}
	if rep.Metrics["字节比"] != "2.000" {
		t.Fatalf("NAT 两段各一次应算出 2.000，实际 %s", rep.Metrics["字节比"])
	}
	noted := false
	for _, f := range rep.Soft {
		if f.What != "" {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("字节翻倍必须留下提示，否则没人知道总量不精确：\n%s", rep)
	}
}

// TestNATOverLimitFails：NAT 上限写 2.05，算成 3 倍必须红。
func TestNATOverLimitFails(t *testing.T) {
	w := simnet.NAT(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	s := perfect(w)
	for i := range s.edges {
		s.edges[i].Bytes = s.edges[i].Bytes * 3 / 2
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("超过 NAT 上限没被抓到：\n%s", rep)
	}
}

// TestLossIsNotADefect 丢包导致字节偏少不是缺陷（分母是真值）。
func TestLossIsNotADefect(t *testing.T) {
	w := simnet.PartialObservation(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	s := perfect(w)
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("漏采被误判成缺陷：\n%s", rep)
	}
}

// ---- 出口与代理：新场景的判据本身要有判别力 ----
//
// 这两类设备是"图上最该出现、却最容易缺席"的：路由器只在以太网头里留一个 MAC，
// 代理背后的终端只在请求头里留一个地址。判据写软了（比如"有节点就算过"），
// 产品少认一台设备也照样绿，那这几条场景就白造了。

func egressWorld() *simnet.World {
	return simnet.Egress(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
}

func proxyWorld() *simnet.World {
	return simnet.Proxy(7, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
}

// TestEgressPerfectPasses 出口场景的完美图必须通过（否则是判据自己错）。
func TestEgressPerfectPasses(t *testing.T) {
	w := egressWorld()
	s := perfect(w)
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("完美图被判失败，校验器有问题：\n%s", rep)
	}
	if got := rep.Metrics["出网路径缺边"]; got != "0" {
		t.Errorf("完美图不该缺出网路径边，实际 %s", got)
	}
}

// TestMissingGatewayRoleFails 网关没被识别成 gateway 必须红。
func TestMissingGatewayRoleFails(t *testing.T) {
	w := egressWorld()
	s := perfect(w)
	for i := range s.nodes {
		if s.nodes[i].Roles != nil {
			s.nodes[i].Roles = nil
		}
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("网关角色丢了没被抓到：\n%s", rep)
	}
	if !hasFinding(rep, "没被识别成") {
		t.Fatalf("报的不是角色问题：\n%s", rep)
	}
}

// TestMissingGatewayEdgeFails 主机到网关的边缺失必须红。
//
// 删的是"主机 → 网关"这一对上的**所有**边：只要还剩任何一条（哪怕只是 DNS
// 查询那条流量边），拓扑上那个必经点就在，不该报缺。所以这里删干净，
// 检验的是"一点痕迹都没有"这种最坏情况。
func TestMissingGatewayEdgeFails(t *testing.T) {
	w := egressWorld()
	s := perfect(w)
	gwKey := ""
	for i := range s.nodes {
		if s.nodes[i].MAC != "" && len(s.nodes[i].IPs) > 1 {
			gwKey = s.nodes[i].Key // 一台设备两个 IP = 网关
		}
	}
	if gwKey == "" {
		t.Fatal("场景里找不到「一台设备两个 IP」的网关，构造有问题")
	}
	kept := s.edges[:0]
	for _, e := range s.edges {
		if e.Src == gwKey || e.Dst == gwKey {
			continue
		}
		kept = append(kept, e)
	}
	s.edges = kept
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("出网路径边全删了还没红：\n%s", rep)
	}
	if !hasFinding(rep, "没有边") {
		t.Fatalf("报的不是缺边问题：\n%s", rep)
	}
}

// TestProxyPerfectPasses 代理场景的完美图必须通过。
func TestProxyPerfectPasses(t *testing.T) {
	w := proxyWorld()
	s := perfect(w)
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if !rep.Pass() {
		t.Fatalf("完美图被判失败，校验器有问题：\n%s", rep)
	}
}

// TestMissingXFFClientFails XFF 里的真实客户端没被还原必须红。
//
// 这是代理场景存在的全部意义：不还原 XFF，图上就是"一台代理访问了所有业务"，
// 真正发起请求的终端一台都不存在——而被攻陷的往往正是那些终端。
func TestMissingXFFClientFails(t *testing.T) {
	w := proxyWorld()
	s := perfect(w)
	kept := s.nodes[:0]
	dropped := ""
	for _, n := range s.nodes {
		if hasLabelOf(n.Labels, "xff-client") {
			dropped = n.IPs[0]
			continue
		}
		kept = append(kept, n)
	}
	if dropped == "" {
		t.Fatal("场景里没有 xff-client 节点，构造有问题")
	}
	s.nodes = kept
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("XFF 客户端丢了没被抓到：\n%s", rep)
	}
	if !hasFinding(rep, "XFF 里的真实客户端") {
		t.Fatalf("报的不是 XFF 还原问题：\n%s", rep)
	}
}

// TestMissingProxyRoleFails 代理没被识别成 proxy 必须红。
func TestMissingProxyRoleFails(t *testing.T) {
	w := proxyWorld()
	s := perfect(w)
	for i := range s.nodes {
		if s.nodes[i].Roles != nil {
			s.nodes[i].Roles = nil
		}
	}
	rep := truthcheck.Check(w, s.nodes, s.edges)
	if rep.Pass() {
		t.Fatalf("代理角色丢了没被抓到：\n%s", rep)
	}
}

func hasFinding(rep *truthcheck.Report, sub string) bool {
	for _, f := range rep.Hard {
		if strings.Contains(f.What, sub) {
			return true
		}
	}
	return false
}

func hasLabelOf(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
