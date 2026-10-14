package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// ---------- 反代（SPEC §5） ----------

// evalReverseProxy 单内网 IP 对外映射 Host 域名数 > 阈值（默认 10）→ 打标签。
func evalReverseProxy(rc *ruleContext) []model.RiskEvent {
	threshold := rc.d.Cfg.ReverseProxyHosts
	if threshold <= 0 {
		threshold = 10
	}
	hostsByNode := map[int64]map[string]bool{}
	for i := range rc.sessions {
		s := &rc.sessions[i]
		host := s.HTTPHost
		if host == "" {
			host = s.SNI
		}
		if host == "" || !topology.IsPrivate(s.FiveTuple.SrcIP) {
			continue
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}
		set := hostsByNode[node.ID]
		if set == nil {
			set = map[string]bool{}
			hostsByNode[node.ID] = set
		}
		set[strings.ToLower(host)] = true
	}

	var out []model.RiskEvent
	for nodeID, set := range hostsByNode {
		if len(set) <= threshold {
			continue
		}
		hosts := make([]string, 0, len(set))
		for h := range set {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out = append(out, model.RiskEvent{
			Type:   model.EventTypeReverseProxy,
			NodeID: nodeID,
			Level:  model.RiskMid,
			Title:  "疑似反向代理：单 IP 映射多 Host",
			Detail: fmt.Sprintf("节点对外映射 Host 域名数 %d，超过阈值 %d（仅标签）", len(hosts), threshold),
			Evidence: map[string]string{
				"host_count": strconv.Itoa(len(hosts)),
				"threshold":  strconv.Itoa(threshold),
				"hosts":      strings.Join(hosts, ","),
			},
		})
	}
	return out
}

// ---------- 未知出口（SPEC §5 + §10.4 基线规则） ----------

// egressTracker 1h 滚动窗口统计单节点对外服务端口/链路数。
type egressTracker struct {
	// 历史基线：学习期/正常运行中观察到的窗口峰值
	baseline map[int64]int
}

func newEgressTracker() *egressTracker {
	return &egressTracker{baseline: map[int64]int{}}
}

// evalUnknownEgress 内网节点对外服务端口/链路数突增超基线：
// 触发条件：当前 1h 窗口计数 > max(3×历史基线, 20)；
// 服务启动后前 LearningPeriod（默认 10min）为学习期，不产出事件。
func evalUnknownEgress(rc *ruleContext) []model.RiskEvent {
	now := rc.now
	windowStart := now.Add(-time.Hour)

	// 统计：内网节点 → 对外 (dstIP:dstPort) 去重链路数（近 1h 有流量的会话）
	counts := map[int64]map[string]bool{}
	for i := range rc.sessions {
		s := &rc.sessions[i]
		if !topology.IsPrivate(s.FiveTuple.SrcIP) || topology.IsPrivate(s.FiveTuple.DstIP) {
			continue
		}
		if s.LastSeen.Before(windowStart) {
			continue
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
		if node == nil {
			continue
		}
		set := counts[node.ID]
		if set == nil {
			set = map[string]bool{}
			counts[node.ID] = set
		}
		set[s.FiveTuple.DstIP+":"+strconv.Itoa(int(s.FiveTuple.DstPort))] = true
	}

	learning := now.Sub(rc.d.started) < rc.d.LearningPeriod
	t := rc.d.egress
	var out []model.RiskEvent
	for nodeID, set := range counts {
		count := len(set)
		base := t.baseline[nodeID]
		threshold := 3 * base
		if threshold < 20 {
			threshold = 20
		}
		if learning {
			// 学习期：只累计基线，不产出事件
			if count > base {
				t.baseline[nodeID] = count
			}
			continue
		}
		if count > threshold {
			out = append(out, model.RiskEvent{
				Type:   model.EventTypeUnknownEgress,
				NodeID: nodeID,
				Level:  model.RiskMid,
				Title:  "未知出口：对外服务端口/链路数突增",
				Detail: fmt.Sprintf("节点近 1h 对外链路数 %d，超过基线阈值 %d（基线 %d）（仅标签）", count, threshold, base),
				Evidence: map[string]string{
					"egress_links_1h": strconv.Itoa(count),
					"baseline":        strconv.Itoa(base),
					"threshold":       strconv.Itoa(threshold),
				},
			})
			continue // 触发时不污染基线
		}
		if count > base {
			t.baseline[nodeID] = count // 正常范围内缓慢抬升基线
		}
	}
	return out
}
