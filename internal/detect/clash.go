package detect

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// Clash/V2Ray 特征阈值
const (
	clashMinShortConns  = 10 // 高频短间隔外联：短会话数下限
	clashMinDistinctDst = 5  // 持续陌生目的：不同公网 /24 下限
	clashShortConnSec   = 30 // 短会话时长上限
	clashHighDistinct   = 20 // 陌生目的达到该值升级为 high
)

// looksRandomSNI 启发式判定随机/罕见域名：
// 主标签足够长且信息熵高（DGA/随机串特征），或不含常见元音结构。
func looksRandomSNI(sni string) bool {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni == "" {
		return false
	}
	parts := strings.Split(sni, ".")
	if len(parts) < 2 {
		return false
	}
	label := parts[len(parts)-2] // 主标签
	if len(label) < 10 {
		return false
	}
	var alnum float64
	freq := map[rune]int{}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			alnum++
			freq[r]++
		}
	}
	if alnum < float64(len(label))*0.9 { // 含大量连字符等不判
		return false
	}
	// 香农熵
	var entropy float64
	for _, c := range freq {
		p := float64(c) / float64(len([]rune(label)))
		entropy -= p * math.Log2(p)
	}
	return entropy > 3.5
}

// evalClash Clash/V2Ray 检测：随机/罕见 SNI + 高频短间隔公网外联 + 持续陌生目的。
// 三项同时满足 → mid；陌生目的 /24 数 ≥ 20 → high。
func evalClash(rc *ruleContext) []model.RiskEvent {
	type acc struct {
		randomSNIs map[string]bool
		shortConns int
		dstSubnets map[string]bool
		snis       []string
	}
	perNode := map[int64]*acc{}

	for i := range rc.sessions {
		s := &rc.sessions[i]
		if !topology.IsPrivate(s.FiveTuple.SrcIP) || topology.IsPrivate(s.FiveTuple.DstIP) {
			continue // 只看内网→公网
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}
		a := perNode[node.ID]
		if a == nil {
			a = &acc{randomSNIs: map[string]bool{}, dstSubnets: map[string]bool{}}
			perNode[node.ID] = a
		}
		if s.SNI != "" {
			a.snis = append(a.snis, s.SNI)
			if looksRandomSNI(s.SNI) {
				a.randomSNIs[s.SNI] = true
			}
		}
		if sessionDuration(s).Seconds() < clashShortConnSec {
			a.shortConns++
		}
		a.dstSubnets[subnetOf(s.FiveTuple.DstIP)] = true
	}

	var out []model.RiskEvent
	for nodeID, a := range perNode {
		hasRandom := len(a.randomSNIs) > 0
		hasFrequent := a.shortConns >= clashMinShortConns
		hasStrange := len(a.dstSubnets) >= clashMinDistinctDst
		if !(hasRandom && hasFrequent && hasStrange) {
			continue
		}
		level := model.RiskMid
		if len(a.dstSubnets) >= clashHighDistinct {
			level = model.RiskHigh
		}
		snis := make([]string, 0, len(a.randomSNIs))
		for s := range a.randomSNIs {
			snis = append(snis, s)
		}
		sort.Strings(snis)
		out = append(out, model.RiskEvent{
			Type:   model.EventTypeClash,
			NodeID: nodeID,
			Level:  level,
			Title:  "疑似代理工具（Clash/V2Ray）外联特征",
			Detail: fmt.Sprintf("节点随机/罕见 SNI %d 个，短间隔公网外联 %d 次，陌生目的网段 %d 个（仅标签）",
				len(a.randomSNIs), a.shortConns, len(a.dstSubnets)),
			Evidence: map[string]string{
				"random_snis":          strings.Join(snis, ","),
				"short_conn_count":     strconv.Itoa(a.shortConns),
				"distinct_dst_subnets": strconv.Itoa(len(a.dstSubnets)),
			},
		})
	}
	return out
}

func subnetOf(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return ip
}
