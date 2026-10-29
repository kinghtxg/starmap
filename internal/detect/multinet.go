package detect

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// evalMultiNet 多网融合检测（SPEC §5 + §10.9）。
//
// V1.4 重大改造：政务网/隔离内网场景下，"一机两网"（同一台设备同时接入多个网段）是最关键的违规形态。
// 旧实现只按 NetDomain（手工配置的粗粒度 CIDR，如 192.168.0.0/16）判定，导致
// **同一大域内跨 /24 网段完全漏检**——而这正是真实网络里最常见的形态。
//
// 现改为双维度判定，两个维度都**完全基于被动流量**（不依赖主动扫描）：
//
//	A. 网段维度（核心）：同一设备（同 MAC 合并后的节点）拥有 ≥2 个 /24 网段的 IP
//	   —— 直接对应"一机两网"，网段由流量自动归纳，无需手工配置
//	B. 域维度（补充）：流量命中 ≥2 个 NetDomain（手工配置的业务域）
func evalMultiNet(rc *ruleContext) []model.RiskEvent {
	type hit struct {
		subnets map[string]bool
		domains map[string]bool
	}
	hits := map[int64]*hit{}
	nodes := map[int64]*model.Node{}

	get := func(id int64) *hit {
		h := hits[id]
		if h == nil {
			h = &hit{subnets: map[string]bool{}, domains: map[string]bool{}}
			hits[id] = h
		}
		return h
	}

	// ---- A. 网段维度：遍历全量内网节点，按节点 IP 计算覆盖的 /24 网段 ----
	// 用 AllNodes 而非 Snapshot：Snapshot 会隐藏已聚合网段的成员（V1.4 P0 修复）
	all := rc.d.Engine.AllNodes()
	for i := range all {
		n := &all[i]
		subnets := map[string]bool{}
		for _, ip := range n.IPs {
			if !topology.IsPrivate(ip) {
				continue
			}
			// 跳过"非网段"地址（链路本地、多播、广播）。
			//
			// 链路本地地址不是"网段"，是每块网卡各自一段的本地地址：一台再普通
			// 不过的双栈主机都同时有 192.168.1.x 和 fe80::xxx，把它算进网段维度，
			// 等于把全站绝大多数设备判成"一机两网"——而且是 high 级。
			// 接入真实流量实测时第一个冒出来的就是这条误报，比漏报更伤：
			// 值班的人被这种事件刷几天，后面真事件就不看了。
			if isAuxPeer(ip) {
				continue
			}
			if c := topology.Subnet24(ip); c != "" {
				subnets[c] = true
			}
		}
		if len(subnets) < 2 {
			continue
		}
		h := get(n.ID)
		for c := range subnets {
			h.subnets[c] = true
		}
		nodes[n.ID] = n
	}

	// ---- B. 域维度：跨"已配置的业务域" ----
	// 两条硬约束，缺一条这条规则在真实网络里就退化成"人人都是有罪"：
	//
	//  1. 对端必须是真实单播设备。mDNS(224.0.0.251)、SSDP(239.255.255.x)、
	//     网段广播(.255)、回环这些地址会被 0.0.0.0/0 通配域一口吞下，判成
	//     "命中了 internet 域"，于是任何一台会发 mDNS 的设备都成了"跨域"。
	//     实测：路由器 192.168.31.1 全图只有两条 mDNS 边，却被判 high 一机两网。
	//  2. 必须是非通配域。internet=0.0.0.0/0 只是"其余所有地址"的兜底桶，不是
	//     一条真实网络边界；拿它当跨域的一半证据，等于自我证明。
	for i := range rc.sessions {
		s := &rc.sessions[i]
		node := rc.internalNodeOf(s)
		if node == nil {
			continue
		}
		peer := s.FiveTuple.DstIP
		if peer == s.FiveTuple.SrcIP || !topology.IsPrivate(peer) || isAuxPeer(peer) {
			continue
		}
		peerDomain, ones := rc.d.Engine.MatchDomainPrefix(peer)
		if peerDomain == "" || ones == 0 {
			continue
		}
		h := get(node.ID)
		nodes[node.ID] = node
		h.domains[peerDomain] = true
	}

	// 节点自身归属域只在"非通配"时才算进跨域集合，
	// 否则一个节点自己就可能凑出 {internet, internet} 这种假跨域。
	for id, node := range nodes {
		if d := ownBusinessDomain(rc.d.Engine, node); d != "" {
			get(id).domains[d] = true
		}
	}

	var out []model.RiskEvent
	for nodeID, h := range hits {
		subnets := sortedKeys(h.subnets)
		domains := sortedKeys(h.domains)
		if len(subnets) < 2 && len(domains) < 2 {
			continue
		}
		node := nodes[nodeID]
		if node == nil {
			continue
		}
		var basis []string
		var detailParts []string
		if len(subnets) >= 2 {
			basis = append(basis, "subnet")
			detailParts = append(detailParts, "跨网段（/24）："+strings.Join(subnets, ", "))
		}
		if len(domains) >= 2 {
			basis = append(basis, "domain")
			detailParts = append(detailParts, "跨网络域："+strings.Join(domains, ", "))
		}
		out = append(out, model.RiskEvent{
			Type:   model.EventTypeMultiNet,
			NodeID: nodeID,
			Level:  model.RiskHigh,
			Title:  "多网融合：同一设备接入多个网段/网络域",
			Detail: fmt.Sprintf("设备（%s）%s（仅标签，不定性）", nodeKeyOrIP(node), strings.Join(detailParts, "；")),
			Evidence: map[string]string{
				"basis":   strings.Join(basis, ","),
				"subnets": strings.Join(subnets, ","),
				"domains": strings.Join(domains, ","),
				"mac":     node.MAC,
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// isAuxPeer 判断地址是否"不构成一个对端设备"：多播、广播、回环、未指定，
// 以及链路本地地址（IPv4 169.254/16、IPv6 fe80::/10）。
//
// 判定"一机两网"时，这类地址既不是一个网段，也不是一个业务对端。它们唯一的
// 共同点是会被 0.0.0.0/0 通配域匹配上，从而伪造出"跨域"证据。
func isAuxPeer(ipStr string) bool {
	if topology.IsAuxAddr(ipStr) {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLinkLocalUnicast()
}

// ownBusinessDomain 返回节点自身归属的**业务域**（通配域不算）。
// 节点可能挂了多个地址（v4/v6 双栈、多网卡），取第一个命中了实域的结果。
func ownBusinessDomain(e *topology.Engine, n *model.Node) string {
	for _, ip := range n.IPs {
		if !topology.IsPrivate(ip) || isAuxPeer(ip) {
			continue
		}
		if name, ones := e.MatchDomainPrefix(ip); name != "" && ones > 0 {
			return name
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func nodeKeyOrIP(n *model.Node) string {
	if n.NodeKey != "" {
		return n.NodeKey
	}
	if len(n.IPs) > 0 {
		return n.IPs[0]
	}
	return fmt.Sprintf("node-%d", n.ID)
}
