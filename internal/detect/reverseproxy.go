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

// evalReverseProxy 单内网 IP 作为**服务端**承载的 Host 域名数 > 阈值（默认 10）→ 打标签。
//
// 为什么必须看服务端方向：反代的特征是"一个入口 IP 后面挂多个站点"，只有在该 IP
// **接收**请求、并且请求里的 Host/SNI 各不相同的时候，这个特征才成立。
//
// 早期实现按"源 IP"统计（谁发出了带 SNI 的请求就记在谁头上），等于在描述"客户端
// 上网"：一台普通 PC 一天访问几十个站点，SNI 天然各不相同，必然超过阈值。
// 接入真实流量实测，第一次评估就在值班主机上刷出 "对外映射 Host 33 个" 的反代事件，
// 名单里全是 bilibili / 微软 / 百度网盘 / WPS —— 那只是这台机器在上网。
// 方向搞反了，这条规则在真实网络里 100% 误报，而且是 mid 级噪音，必须停在源头。
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
		if host == "" {
			continue
		}
		// 只看服务端侧：目的地址是内网的会话，才可能是"某台内网设备在对外提供站点"。
		// 目的地址是公网的，一律是别人在提供服务，与反代无关（CDN 单 IP 多 Host 的
		// 误报也一并消失——那是人家的基础设施，不是我们的资产）。
		if !topology.IsPrivate(s.FiveTuple.DstIP) {
			continue
		}
		node := rc.d.Engine.NodeByIP(s.FiveTuple.DstIP)
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
			Detail: fmt.Sprintf("节点作为服务端承载 Host 域名数 %d，超过阈值 %d（仅标签）", len(hosts), threshold),
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
