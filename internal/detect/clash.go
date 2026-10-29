package detect

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

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

// looksRandomSNI 启发式判定随机/罕见域名（DGA/随机子域）。
//
// 三个条件同时满足才算：主标签够长、香农熵够高、**且含数字**。
//
// "含数字"这一条是真实流量打出来的教训：最早只看"够长 + 熵高"，
// 把 `alipayobjects.com`（支付宝静态资源域）判成了随机串——`alipayobjects`
// 13 个字符、全小写、熵自然高，完美落在旧阈值里。于是值班主机第一次被评估
// 就成了"疑似 Clash/V2Ray 外联 high"。真实的 DGA/随机子域几乎必含数字，
// 而品牌词几乎不含，这一条几乎没有成本，却挡掉了绝大部分误报。
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
	if len(label) < 12 {
		return false
	}
	var alnum float64
	var hasDigit bool
	freq := map[rune]int{}
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
			alnum++
			hasDigit = true
			freq[r]++
		case r >= 'a' && r <= 'z':
			alnum++
			freq[r]++
		}
	}
	if !hasDigit {
		return false
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
	// 香农熵受长度上限约束：n 个字符全不重复时最大也只有 log2(n)。
	// 所以绝对阈值是错的——3.8 意味着标签至少 14 个字符才可能达标，
	// 而 DGA 主标签常见长度是 10~12。改成对 log2(len) 归一化，
	// 衡量"字符有多不重复"，与长度解耦。
	if entropy < 0.9*math.Log2(float64(len([]rune(label)))) {
		return false
	}
	return true
}

// evalClash Clash/V2Ray 检测：随机/罕见 SNI + 高频短间隔公网外联 + 持续陌生目的。
// 三项同时满足 → mid；陌生目的 /24 数 ≥ 20 → high。
//
// 统计范围限定在最近 1h（与 unknown_egress 同口径）：原来遍历整张会话表，
// 于是一台开机两天的机器累计了 90 多个公网 /24，被当成"持续陌生目的"——
// 那是"历史访问过的站点总数"，不是"当前异常行为"。凡是"没时间窗的累计计数
// + 阈值"这种组合，在没有攻击者的情况下也会随时间单调撞线。
func evalClash(rc *ruleContext) []model.RiskEvent {
	// 时间窗锚点取"观测到的最新会话时间"，而不是墙钟。
	//
	// 直接拿 time.Now() 做锚点，回放一条历史 PCAP 时全部会话都落在 1h 之前，
	// 于是整条规则静默零事件——这不是"没有异常"，而是"根本没看"。
	// 导入归档流量做复盘是这个产品的主要用法之一，窗口必须跟着数据走。
	// 在线场景下最新会话时间 ≈ 现在，这个锚点与墙钟等价。
	type acc struct {
		randomSNIs map[string]bool
		shortConns int
		dstSubnets map[string]bool
	}
	perNode := map[int64]*acc{}
	// nodeSeen 每个节点自己的"最新一次活动时间"。
	//
	// 时间窗必须按节点算，不能用全局时钟，也不该用全局最新会话时间：
	//   · 用墙钟（time.Now）→ 回放历史 PCAP 时全部会话都在 1h 之前，
	//     整条规则静默零事件——那不是"没有异常"，是"根本没看"；
	//   · 用全局最新会话时间 → 一次导入多个不同时间线的 PCAP（复盘时很常见），
	//     时间线靠后的那个场景会把靠前的场景整段切出窗口。
	// 按节点取锚点，语义也最自然：判断的是"这台机器最近一小时干了什么"。
	nodeSeen := map[int64]time.Time{}

	// 第一遍：按节点求最新活动时间
	for i := range rc.sessions {
		s := &rc.sessions[i]
		if !topology.IsPrivate(s.FiveTuple.SrcIP) || topology.IsPrivate(s.FiveTuple.DstIP) {
			continue
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}
		if s.LastSeen.After(nodeSeen[node.ID]) {
			nodeSeen[node.ID] = s.LastSeen
		}
	}

	// 第二遍：只统计各节点自己窗口内的会话
	for i := range rc.sessions {
		s := &rc.sessions[i]
		if !topology.IsPrivate(s.FiveTuple.SrcIP) || topology.IsPrivate(s.FiveTuple.DstIP) {
			continue // 只看内网→公网
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}
		anchor := nodeSeen[node.ID]
		if anchor.IsZero() || s.LastSeen.Before(anchor.Add(-time.Hour)) {
			continue // 不在该节点最近一小时的窗口内
		}
		a := perNode[node.ID]
		if a == nil {
			a = &acc{randomSNIs: map[string]bool{}, dstSubnets: map[string]bool{}}
			perNode[node.ID] = a
		}
		if s.SNI != "" && looksRandomSNI(s.SNI) {
			a.randomSNIs[s.SNI] = true
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
