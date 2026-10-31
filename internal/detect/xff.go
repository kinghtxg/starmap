package detect

import (
	"fmt"
	"sort"
	"strings"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// ---------- 七层转发链可疑（V1.8） ----------

// evalXFFSpoof 识别 X-Forwarded-For 自相矛盾的请求。
//
// 正向识别（"这是代理、背后是谁"）由 topology 层的节点标签承担，不产出事件；
// 这里只处理**明确矛盾**信号，属于"只打标签、不定性"的边界：
//
//	① XFF 首跳 == 观测源本身：请求声称自己来自自己，正常代理不会这样写
//	② X-Real-IP 与 XFF 首跳不一致：两个头互相矛盾，通常是被上游改过
//
// 真实危害：XFF 是客户端可写文本，下游若有基于 XFF 的 IP 白名单/审计，
// 伪造即可绕过或污染日志。因此给 mid，只提示复核。
func evalXFFSpoof(rc *ruleContext) []model.RiskEvent {
	type hit struct {
		reasons map[string]bool
		samples []string
	}
	byNode := map[int64]*hit{}

	for i := range rc.sessions {
		s := &rc.sessions[i]
		if len(s.XFF) == 0 && s.XRealIP == "" {
			continue
		}
		// 只在请求源为内网时判定：公网侧不做定性
		if !topology.IsPrivate(s.FiveTuple.SrcIP) {
			continue
		}
		node := rc.nodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}

		var reasons []string
		first := ""
		if len(s.XFF) > 0 {
			first = s.XFF[0]
		}
		if first != "" && first == s.FiveTuple.SrcIP {
			reasons = append(reasons, "self_declared")
		}
		if first != "" && s.XRealIP != "" && first != s.XRealIP {
			reasons = append(reasons, "header_conflict")
		}
		if len(reasons) == 0 {
			continue
		}

		h := byNode[node.ID]
		if h == nil {
			h = &hit{reasons: map[string]bool{}}
			byNode[node.ID] = h
		}
		for _, r := range reasons {
			h.reasons[r] = true
		}
		if len(h.samples) < 5 {
			h.samples = append(h.samples, fmt.Sprintf("XFF=[%s] X-Real-IP=%s",
				strings.Join(s.XFF, ","), orDash(s.XRealIP)))
		}
	}

	var out []model.RiskEvent
	for nodeID, h := range byNode {
		keys := make([]string, 0, len(h.reasons))
		for k := range h.reasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sort.Strings(h.samples)
		title := "疑似伪造 X-Forwarded-For：转发头自相矛盾"
		if len(keys) == 1 && keys[0] == "self_declared" {
			title = "疑似伪造 X-Forwarded-For：声称来源即自身"
		}
		out = append(out, model.RiskEvent{
			Type:   model.EventTypeXFFSpoof,
			NodeID: nodeID,
			Level:  model.RiskMid,
			Title:  title,
			Detail: "X-Forwarded-For 是客户端可写文本，正常情况下由代理逐跳追加。（仅标签）",
			Evidence: map[string]string{
				"reason":  strings.Join(keys, ","),
				"samples": strings.Join(h.samples, " | "),
			},
		})
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
