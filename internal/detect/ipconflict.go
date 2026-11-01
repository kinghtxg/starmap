package detect

import (
	"fmt"
	"sort"
	"strings"

	"starmap/internal/model"
)

// evalIPConflict IP 冲突检测：同一个 IP 上同时存在两台（或多台）MAC 不同的设备。
//
// # 为什么这条规则值得单独存在
//
// 被动流量里，"一个 IP 对应两个 MAC"是极少数的**确定性**信号之一：不需要行为
// 建模、不需要基线学习，看到就是看到了。它对应三种现场：
//
//  1. 静态地址配错 —— 两台机器配了同一个地址，谁的服务时通时不通，运维能查一周；
//  2. DHCP 地址池重叠 / 私接路由器 —— 同地址被反复分配，租约表里看不出来；
//  3. ARP 欺骗 —— 攻击者把自己的 MAC 绑到网关或服务器 IP 上，这是内网横向的
//     第一步，也是后续中间人、凭据抓取的前提。
//
// 前两种是运维事故，第三种是正在发生的攻击；三种在流量层面的表现完全一样，
// 所以这条规则只**打标签、给出证据**，定性与处置交给人——这和 §5 "所有规则只打
// 标签，不做定性"一致。
//
// # 为什么用"按 IP 分组"而不是读引擎的 ip-conflict 标签
//
// 引擎在建节点时已经会拆分并打标（见 topology.LabelIPConflict），但标签是
// 内存态、随节点恢复走；规则这边自己按 IP 分组重算一遍，好处是：重启后从库里
// 捞出来的老节点同样能被判出来，不依赖"这次运行期间恰好见过冲突"。两处判断
// 一致时互不矛盾，不一致时以规则为准（规则的输入更全：全量节点）。
func evalIPConflict(rc *ruleContext) []model.RiskEvent {
	// ip → 该地址上的节点（只收 MAC 明确的：没有 MAC 参与的节点无法证明是"另一台"）
	byIP := map[string][]*model.Node{}
	all := rc.allNodes()
	for i := range all {
		n := &all[i]
		if n.MAC == "" {
			continue
		}
		if hasNodeLabel(n, "subnet-agg") || hasNodeLabel(n, "external-agg") {
			continue // 聚合节点不是实体设备
		}
		for _, ip := range n.IPs {
			if ip == "" {
				continue
			}
			byIP[ip] = append(byIP[ip], n)
		}
	}

	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var out []model.RiskEvent
	for _, ip := range ips {
		nodes := byIP[ip]
		if len(nodes) < 2 {
			continue
		}
		macs := map[string]bool{}
		for _, n := range nodes {
			macs[n.MAC] = true
		}
		if len(macs) < 2 {
			continue // 同一个 MAC 的多条记录（历史遗留行），不是冲突
		}

		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		owner := nodes[0]
		macList := make([]string, 0, len(macs))
		for m := range macs {
			macList = append(macList, m)
		}
		sort.Strings(macList)

		keys := make([]string, 0, len(nodes))
		for _, n := range nodes {
			keys = append(keys, nodeKeyOrIP(n))
		}

		out = append(out, model.RiskEvent{
			// 事件挂在最早建出的那个节点上：既稳定（重启不乱跳），又保证同一冲突
			// 只出一条事件——挂在最新节点上的话，每来一台新机器就多出一条。
			Type:   model.EventTypeIPConflict,
			NodeID: owner.ID,
			Level:  model.RiskMid,
			Title:  "IP 冲突：同一地址上出现多台设备",
			Detail: fmt.Sprintf("地址 %s 上有 %d 台设备（MAC：%s）。可能是地址配错、DHCP 池重叠，也可能是 ARP 欺骗（仅标签，不定性）",
				ip, len(nodes), strings.Join(macList, " / ")),
			Evidence: map[string]string{
				"ip":    ip,
				"macs":  strings.Join(macList, ","),
				"nodes": strings.Join(keys, ","),
				"count": fmt.Sprint(len(nodes)),
			},
		})
	}
	return out
}

func hasNodeLabel(n *model.Node, want string) bool {
	for _, l := range n.Labels {
		if l == want {
			return true
		}
	}
	return false
}
