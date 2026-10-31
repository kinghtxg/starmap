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
// 政务网/隔离内网场景下，"一机两网"（同一台设备同时接入多个网段）是最关键的违规形态。
// 判定对象是**设备自身接入的地址**，两个维度：
//
//	A. 网段维度（核心）：同一设备（同 MAC 合并后的节点）拥有 ≥2 个 /24 网段的 IP
//	   —— 直接对应"一机两网"，网段由流量自动归纳，无需手工配置
//	B. 域维度（补充）：同一设备的自有 IP 命中 ≥2 个 NetDomain（手工配置的业务域）
//
// # 为什么只看"自有地址"，不看"访问过谁"（v1.6.0 修复）
//
// 旧实现把会话的**对端**所属域也算进设备的域集合，于是判定退化成
// "这台机器访问过两个网段"。这两件事完全不同：
//
//   - 接入多个网段 = 设备长了两条腿（违规把设备同时插进内网和互联网）；
//   - 访问多个网段 = 设备在正常干活（政务网里一台 PC 同时开办公系统和业务
//     系统，天然就跨两个域）。
//
// 默认网络域是 gov=10.0.0.0/8、office=172.16.0.0/12、internet=0.0.0.0/0，
// 于是"10.x 的主机访问 172.16.x 的服务"这种最普通的业务流量，就被判成
// "一机两网 high"。压测实测：4 万个节点的合成网络里，这条规则一轮产出
// 3.9 万个 high 事件，占全量候选的 99.7%，把真正的事件全埋了，同时把
// 每轮评估从 200ms 拖到 1.9s。
//
// 现场后果比性能更严重：值班的人被同一台机器的 4 万条 high 刷屏一周之后，
// 就不再打开这个页面了。规则宁可漏，也不能把"正常上网"判成违规。
func evalMultiNet(rc *ruleContext) []model.RiskEvent {
	type hit struct {
		subnets map[string]bool
		domains map[string]bool
	}
	hits := map[int64]*hit{}
	nodes := map[int64]*model.Node{}

	// 遍历全量内网节点：用 AllNodes 而非 Snapshot——Snapshot 会隐藏已聚合网段的
	// 成员，而"一机两网"的主机恰恰常常因为多网段而被聚合掉（V1.4 P0 修复）。
	all := rc.allNodes()
	for i := range all {
		n := &all[i]
		if len(n.IPs) < 2 {
			continue // 单地址设备不可能跨网段/跨域，先挡掉绝大多数节点
		}
		var subnets, domains map[string]bool
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
				if subnets == nil {
					subnets = map[string]bool{}
				}
				subnets[c] = true
			}
			// 通配域（0.0.0.0/0、::/0）不算域：它只是"其余所有地址"的兜底桶，
			// 不是一个真实的网络边界。（ones == 0 即通配）
			if name, ones := rc.matchDomain(ip); name != "" && ones > 0 {
				if domains == nil {
					domains = map[string]bool{}
				}
				domains[name] = true
			}
		}
		if len(subnets) < 2 && len(domains) < 2 {
			continue
		}
		hits[n.ID] = &hit{subnets: subnets, domains: domains}
		nodes[n.ID] = n
	}

	out := make([]model.RiskEvent, 0, len(hits))
	for nodeID, h := range hits {
		node := nodes[nodeID]
		if node == nil {
			continue
		}
		subnets := sortedKeys(h.subnets)
		domains := sortedKeys(h.domains)
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
				"ips":     strings.Join(node.IPs, ","),
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
