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
			// 跳过链路本地地址（IPv4 169.254/16、IPv6 fe80::/10）。
			//
			// 链路本地地址不是"网段"，是每块网卡各自一段的本地地址：一台再普通
			// 不过的双栈主机都同时有 192.168.1.x 和 fe80::xxx，把它算进网段维度，
			// 等于把全站绝大多数设备判成"一机两网"——而且是 high 级。
			// 接入真实流量实测时第一个冒出来的就是这条误报，比漏报更伤：
			// 值班的人被这种事件刷几天，后面真事件就不看了。
			if isLinkLocalAddr(ip) {
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

	// ---- B. 域维度：沿用会话侧跨域统计（补充手工配置的业务域） ----
	for i := range rc.sessions {
		s := &rc.sessions[i]
		node := rc.internalNodeOf(s)
		if node == nil {
			continue
		}
		peer := s.FiveTuple.DstIP
		if peer == s.FiveTuple.SrcIP || !topology.IsPrivate(peer) {
			continue
		}
		peerDomain := rc.d.Engine.MatchDomain(peer)
		if peerDomain == "" {
			continue
		}
		h := get(node.ID)
		nodes[node.ID] = node
		h.domains[peerDomain] = true
		if node.Domain != "" {
			h.domains[node.Domain] = true
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

// isLinkLocalAddr 判断是否链路本地地址（IPv4 169.254/16、IPv6 fe80::/10）。
// 这类地址按网卡各自分配，不构成"网段"，不能拿来判定一机两网。
func isLinkLocalAddr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
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
