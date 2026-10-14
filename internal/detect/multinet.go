package detect

import (
	"fmt"
	"sort"
	"strings"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// evalMultiNet 多网域融合检测（SPEC §5 + §10.9）：
// 同节点 / 同 MAC / 同首跳网关 MAC 的流量命中 ≥2 个 NetDomain → high。
func evalMultiNet(rc *ruleContext) []model.RiskEvent {
	// 分组 key：优先节点自身（同节点），再按 MAC，再按首跳网关 MAC
	type group struct {
		nodeIDs map[int64]bool
		domains map[string]bool
	}
	groups := map[string]*group{}
	add := func(key string, nodeID int64, domain string) {
		if key == "" || domain == "" {
			return
		}
		g := groups[key]
		if g == nil {
			g = &group{nodeIDs: map[int64]bool{}, domains: map[string]bool{}}
			groups[key] = g
		}
		g.nodeIDs[nodeID] = true
		g.domains[domain] = true
	}

	for i := range rc.sessions {
		s := &rc.sessions[i]
		node := rc.internalNodeOf(s)
		if node == nil {
			continue
		}
		// 该会话对端命中的网络域：仅统计内网对端的域归属
		// （公网对端属互联网出口，不计入"多网域融合"，否则任何上网行为都会误命中）
		peer := s.FiveTuple.DstIP
		if peer == s.FiveTuple.SrcIP || !topology.IsPrivate(peer) {
			continue
		}
		peerDomain := rc.d.Engine.MatchDomain(peer)
		if peerDomain == "" {
			continue
		}
		// 节点自身域也计入：节点域 ≠ 对端域 → 跨域
		selfDomain := node.Domain

		add("node:"+nodeIDStr(node.ID), node.ID, peerDomain)
		if selfDomain != "" {
			add("node:"+nodeIDStr(node.ID), node.ID, selfDomain)
		}
		if node.MAC != "" {
			add("mac:"+node.MAC, node.ID, peerDomain)
			if selfDomain != "" {
				add("mac:"+node.MAC, node.ID, selfDomain)
			}
		}
		if gw := rc.d.Engine.GatewayMAC(node.ID); gw != "" {
			add("gw:"+gw, node.ID, peerDomain)
			if selfDomain != "" {
				add("gw:"+gw, node.ID, selfDomain)
			}
		}
	}

	emitted := map[int64]bool{}
	var out []model.RiskEvent
	for key, g := range groups {
		if len(g.domains) < 2 {
			continue
		}
		domains := make([]string, 0, len(g.domains))
		for d := range g.domains {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		// 对组内每个节点发事件（同节点去重）
		for nodeID := range g.nodeIDs {
			if emitted[nodeID] {
				continue
			}
			emitted[nodeID] = true
			out = append(out, model.RiskEvent{
				Type:   model.EventTypeMultiNet,
				NodeID: nodeID,
				Level:  model.RiskHigh,
				Title:  "多网域融合：流量命中多个网络域",
				Detail: fmt.Sprintf("节点（分组 %s）流量命中网络域：%s（仅标签）", key, strings.Join(domains, ", ")),
				Evidence: map[string]string{
					"domains":   strings.Join(domains, ","),
					"group_key": key,
				},
			})
		}
	}
	return out
}
