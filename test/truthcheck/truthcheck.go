// Package truthcheck 用真值校验星图的输出。
//
// 这个包刻意**不 import internal/topology**：校验器必须独立实现，否则它和被测
// 对象共享同一套假设，测试就永远绿——比如引擎把 /24 当成聚合单位，校验器也照抄
// /24，那"聚合吞掉异常"这件事永远测不出来。这里的判定只依据 simnet 的真值和
// 引擎交出来的原始事实（节点、边），不复用引擎的任何算法。
//
// 判定基准是**探针实际观测到的**（world.Sessions()），不是世界的全部真相。
// 这个区别很重要：链路被探针漏采了，图上没有边是对的；拿真值链路去要求边，
// 测出来的就是"模拟器自己造的丢包"，而不是产品缺陷。
package truthcheck

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"starmap/internal/simnet"
)

// Node 引擎交出来的节点事实（由测试层从 model.Node 转换，本包不认识 model）。
//
// Key 必须与 Edge.Src/Dst 同一命名空间（星图里是节点内部 ID 的字符串形式，
// 聚合节点则是 subnet:/ext: 前缀）——否则"缺边"会全量误报。NodeKey 只用于
// 输出人类可读的身份（mac:/ip:），不参与匹配。
type Node struct {
	Key       string
	NodeKey   string
	IPs       []string
	MAC       string
	FirstSeen time.Time
	Ports     []int
	Labels    []string
	Members   int
}

// Edge 引擎交出来的边事实。
type Edge struct {
	Src, Dst  string
	Protocol  string
	Kind      string
	Bytes     int64
	FirstSeen time.Time
}

// Finding 一条结论。
type Finding struct {
	What string
	Why  string
}

// Report 一个场景的校验结果。
type Report struct {
	Scenario string
	// Hard 违反不变量：产品算错了，必须修。
	Hard []Finding
	// Soft 值得知道但不算错：可能是设计取舍，需要人来判断。
	Soft []Finding
	// Metrics 关键数字，进 CI 日志方便对比趋势。
	Metrics map[string]string
}

// Pass 没有硬失败。
func (r *Report) Pass() bool { return len(r.Hard) == 0 }

// String 输出人类可读的报告。
func (r *Report) String() string {
	var b strings.Builder
	status := "通过"
	if !r.Pass() {
		status = "失败"
	}
	fmt.Fprintf(&b, "[%s] %s  硬失败 %d / 提示 %d\n", r.Scenario, status, len(r.Hard), len(r.Soft))
	keys := make([]string, 0, len(r.Metrics))
	for k := range r.Metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "    %-14s %s\n", k, r.Metrics[k])
	}
	for _, f := range r.Hard {
		fmt.Fprintf(&b, "    ✗ %s —— %s\n", f.What, f.Why)
	}
	for _, f := range r.Soft {
		fmt.Fprintf(&b, "    ! %s —— %s\n", f.What, f.Why)
	}
	return b.String()
}

// Check 用真值校验一次引擎输出。
func Check(w *simnet.World, nodes []Node, edges []Edge) *Report {
	r := &Report{Scenario: w.Name, Metrics: map[string]string{}}

	// ---- 0. 观测事实：探针到底报上来了什么 ----
	//
	// 后面所有"应该有"的断言都从这里出发。真值世界是"世界应该发生什么"，
	// 观测才是"产品拿得到什么"；混用这两者，会把模拟器自己的丢包算成 bug。
	sessions := w.Sessions()
	observedIP := map[string]bool{}
	observedPeer := map[[2]string]bool{}
	observedSrvPort := map[string]map[int]bool{}
	for _, s := range sessions {
		observedIP[s.FiveTuple.SrcIP] = true
		observedIP[s.FiveTuple.DstIP] = true
		observedPeer[ipPair(s.FiveTuple.SrcIP, s.FiveTuple.DstIP)] = true
		if observedSrvPort[s.FiveTuple.DstIP] == nil {
			observedSrvPort[s.FiveTuple.DstIP] = map[int]bool{}
		}
		observedSrvPort[s.FiveTuple.DstIP][int(s.FiveTuple.DstPort)] = true
	}
	r.Metrics["观测会话"] = fmt.Sprint(len(sessions))
	r.Metrics["观测地址"] = fmt.Sprint(len(observedIP))
	r.Metrics["观测端点对"] = fmt.Sprint(len(observedPeer))

	// IP → 节点集合
	ipOwner := map[string][]string{}
	for _, n := range nodes {
		for _, ip := range n.IPs {
			ipOwner[ip] = append(ipOwner[ip], n.Key)
		}
	}
	find := func(ip string) string {
		if v := ipOwner[ip]; len(v) > 0 {
			return v[0]
		}
		return ""
	}

	// 真值里哪些 IP 是多台设备共用的（地址冲突）。判定"一个 IP 只能属于一个节点"
	// 必须先看真值：真值是两台机器抢一个地址时，图上两个节点才是**对的**。
	truthHostsOfIP := map[string][]string{}
	for i := range w.Hosts {
		h := &w.Hosts[i]
		for _, ip := range h.IPs {
			truthHostsOfIP[ip] = append(truthHostsOfIP[ip], h.Name)
		}
	}

	// ---- 1. 同一台设备必须是一个节点（真值里的 IP 集合落到同一节点） ----
	splitHosts := 0
	for i := range w.Hosts {
		h := &w.Hosts[i]
		seen := map[string]bool{}
		anyObserved := false
		for _, ip := range h.IPs {
			if !observedIP[ip] {
				continue
			}
			anyObserved = true
			if k := find(ip); k != "" {
				seen[k] = true
			}
		}
		if !anyObserved {
			continue // 这台设备一条会话都没被观测到，不出现在图上不算错
		}
		if len(seen) > 1 {
			splitHosts++
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("%s 被拆成 %d 个节点", h.Name, len(seen)),
				Why:  fmt.Sprintf("真值里它是一台设备（IP %v 同属一台），拆开就是图上多出幽灵机器，两种拆法都会让人误判", h.IPs),
			})
		}
		if len(seen) == 0 {
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("%s 完全没被发现", h.Name),
				Why:  fmt.Sprintf("真值 IP %v 有会话经过（观测已含），不该缺席", h.IPs),
			})
		}
	}
	r.Metrics["真机数"] = fmt.Sprint(len(w.Hosts))
	r.Metrics["被拆设备"] = fmt.Sprint(splitHosts)

	// ---- 1b. 不能把两台设备并成一个节点 ----
	//
	// 与 1 相反的方向：拆开是"多出幽灵"，并起来是"少了设备"。后者更危险——
	// 两台机器合成一个节点，所有告警、流量、端口都混在一起，图看起来更"干净"，
	// 于是没人会去查。判据只看 MAC：一个节点覆盖了两台 MAC 不同的真机就是错的
	// （IP 冲突场景两台机器 MAC 不同，也应当是两个节点）。
	covered := map[string]map[string]bool{}
	macOf := map[string]string{}
	for i := range w.Hosts {
		h := &w.Hosts[i]
		macOf[h.Name] = h.MAC
		for _, ip := range h.IPs {
			if !observedIP[ip] {
				continue
			}
			k := find(ip)
			if k == "" {
				continue
			}
			if covered[k] == nil {
				covered[k] = map[string]bool{}
			}
			covered[k][h.Name] = true
		}
	}
	swallowed := 0
	mergedKeys := make([]string, 0, len(covered))
	for k := range covered {
		mergedKeys = append(mergedKeys, k)
	}
	sort.Strings(mergedKeys)
	for _, k := range mergedKeys {
		names := covered[k]
		if len(names) < 2 {
			continue
		}
		// IP 冲突场景由 2b 单独判：两台机器确实共用一个地址，靠 IP 区分不了它们，
		// 在这里重复报一遍只会让日志更难读。
		shared := false
		for n := range names {
			for i := range w.Hosts {
				if w.Hosts[i].Name != n {
					continue
				}
				for _, ip := range w.Hosts[i].IPs {
					if len(truthHostsOfIP[ip]) > 1 {
						shared = true
					}
				}
			}
		}
		if shared {
			continue
		}
		macs := map[string]bool{}
		list := make([]string, 0, len(names))
		for n := range names {
			list = append(list, n)
			if macOf[n] != "" {
				macs[macOf[n]] = true
			}
		}
		if len(macs) < 2 {
			continue // 同一台设备的不同观测（同 MAC），本来就该并
		}
		sort.Strings(list)
		swallowed++
		r.Hard = append(r.Hard, Finding{
			What: fmt.Sprintf("%s 被并成 1 个节点", strings.Join(list, " + ")),
			Why:  "两台 MAC 不同的真机合成一台：流量、端口、告警全部混在一起，图反而更\"干净\"，于是没人去查",
		})
	}
	r.Metrics["被吞设备"] = fmt.Sprint(swallowed)

	// ---- 2. 每个 IP 只能属于一个节点（除非真值里就是多台共用） ----
	dupIP := 0
	ipKeys := make([]string, 0, len(ipOwner))
	for ip := range ipOwner {
		ipKeys = append(ipKeys, ip)
	}
	sort.Strings(ipKeys)
	for _, ip := range ipKeys {
		owners := ipOwner[ip]
		allowed := len(truthHostsOfIP[ip])
		if allowed == 0 {
			allowed = 1 // 真值里没有这台设备（幽灵地址），仍只允许一个归属
		}
		if len(owners) > allowed {
			dupIP++
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("IP %s 同时属于 %d 个节点（真值只有 %d 台）", ip, len(owners), allowed),
				Why:  "多出来的归属让同一份流量挂在两条设备上，按 IP 汇总的报表直接翻倍",
			})
		}
	}
	r.Metrics["重复归属 IP"] = fmt.Sprint(dupIP)

	// ---- 2b. 真值里的 IP 冲突必须被拆开，并打上冲突标记 ----
	//
	// 这是场景 IPConflict 的核心：两台机器抢一个地址。拆分只是第一步，
	// 更关键的是**图上要刺眼**——否则两行一模一样的 IP，谁都不会多看一眼，
	// 而现场可能是 ARP 欺骗（攻击者把网关 IP 绑到自己 MAC 上）。
	conflictIPs := make([]string, 0, 2)
	for ip, hosts := range truthHostsOfIP {
		if len(hosts) > 1 {
			conflictIPs = append(conflictIPs, ip)
		}
	}
	sort.Strings(conflictIPs)
	for _, ip := range conflictIPs {
		hosts := truthHostsOfIP[ip]
		if !observedIP[ip] {
			continue
		}
		owners := ipOwner[ip]
		if len(owners) != len(hosts) {
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("IP 冲突没被拆开：%v 抢 %s，图上只有 %d 个节点", hosts, ip, len(owners)),
				Why:  "两台机器合成一台后，冲突现场看起来毫无异常；服务时通时不通这类问题会被查很久",
			})
			continue
		}
		marked := 0
		for _, k := range owners {
			for _, n := range nodes {
				if n.Key == k && hasLabel(n.Labels, "ip_conflict") {
					marked++
				}
			}
		}
		if marked < len(owners) {
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("IP 冲突节点没打标记（%d/%d）", marked, len(owners)),
				Why:  "拆分只是把事实摆出来，不打标记等于两行相同的 IP，值班的人不会注意——ARP 欺骗就是这样被漏掉的",
			})
		}
	}
	r.Metrics["真值冲突 IP"] = fmt.Sprint(len(conflictIPs))

	// ---- 3. 幽灵节点：有 IP 但不在真值里 ----
	truthIP := map[string]bool{}
	for i := range w.Hosts {
		for _, ip := range w.Hosts[i].IPs {
			truthIP[ip] = true
		}
	}
	ghost := 0
	for _, n := range nodes {
		if hasLabel(n.Labels, "subnet-agg") || hasLabel(n.Labels, "external-agg") {
			continue
		}
		if len(n.IPs) == 0 {
			continue // 只有 MAC 的节点（网关推断等）不在本断言范围
		}
		for _, ip := range n.IPs {
			if !truthIP[ip] {
				ghost++
				r.Soft = append(r.Soft, Finding{
					What: fmt.Sprintf("多出节点 %s（IP %s）", displayName(n), ip),
					Why:  "真值里没有这个地址，可能是网关/XFF/归属边派生的节点，需要逐条解释",
				})
				break
			}
		}
	}
	r.Metrics["幽灵节点"] = fmt.Sprint(ghost)

	// ---- 4. 观测到的每对端点都要有边 ----
	edgeSet := map[string]bool{}
	for _, e := range edges {
		if e.Kind != "" && e.Kind != "traffic" {
			continue // 归属边/网关边不是流量，单独看
		}
		edgeSet[pairKey(e.Src, e.Dst)] = true
		edgeSet[pairKey(e.Dst, e.Src)] = true
	}
	missing := 0
	pairs := make([][2]string, 0, len(observedPeer))
	for p := range observedPeer {
		pairs = append(pairs, p)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	for _, p := range pairs {
		a, b := find(p[0]), find(p[1])
		if a == "" || b == "" {
			continue // 端点没建出节点，前面已经报过
		}
		if a == b {
			continue // 同节点内部通信（一机两网自己连自己）不成边
		}
		if !edgeSet[pairKey(a, b)] {
			missing++
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("链路 %s → %s 没有边", p[0], p[1]),
				Why:  "探针确实看见了这条会话，图上却无线：现场看不见这条访问关系",
			})
		}
	}
	r.Metrics["真值链路"] = fmt.Sprint(len(w.Links))
	r.Metrics["缺失边"] = fmt.Sprint(missing)

	// ---- 5. 字节守恒：图上总量不应超过真值（超了就是重复计入） ----
	//
	// 分母必须是**真值**而不是"观测总量"。用观测总量会把判据弄反：
	// 两个探针各报一次同一会话时，观测总量天然是 2 倍，图上 1 倍算出来 0.5，
	// 看着像"丢了一半"，其实正是完美去重。以真值为分母，"等于 1" 才代表准确。
	var truthBytes int64
	for _, l := range w.Links {
		truthBytes += l.Bytes
	}
	var observedBytes int64
	for _, s := range sessions {
		observedBytes += s.BytesUp + s.BytesDown
	}
	var graphBytes int64
	for _, e := range edges {
		if e.Kind != "" && e.Kind != "traffic" {
			continue
		}
		graphBytes += e.Bytes
	}
	r.Metrics["真值字节"] = fmt.Sprint(truthBytes)
	r.Metrics["观测字节"] = fmt.Sprint(observedBytes)
	r.Metrics["图上字节"] = fmt.Sprint(graphBytes)
	if truthBytes > 0 {
		ratio := float64(graphBytes) / float64(truthBytes)
		r.Metrics["字节比"] = fmt.Sprintf("%.3f", ratio)
		r.Metrics["观测倍数"] = fmt.Sprintf("%.2f", float64(observedBytes)/float64(truthBytes))
		limit := 1.02
		if w.MaxByteRatio > 0 {
			limit = w.MaxByteRatio
		}
		switch {
		case ratio > limit:
			r.Hard = append(r.Hard, Finding{
				What: fmt.Sprintf("图上字节是真值的 %.1f%%（上限 %.0f%%）", ratio*100, limit*100),
				Why:  "多出来的部分是重复计入。同一会话被两个观察者算成两条、或重启后又重算一遍，都会落在这项上",
			})
		case ratio > 1.02:
			r.Soft = append(r.Soft, Finding{
				What: fmt.Sprintf("图上字节是真值的 %.1f%%（本场景上限 %.0f%%）", ratio*100, limit*100),
				Why:  "跨 NAT 两段各被看见一次，绕不过去；产品应把这段重复标注出来，而不是对外声称总量精确",
			})
		}
	}

	// ---- 6. 时间边界：节点首次出现不能早于世界开始（考虑最大时钟偏移） ----
	maxSkew := time.Duration(0)
	for _, p := range w.Probes {
		if p.Skew > maxSkew {
			maxSkew = p.Skew
		}
		if -p.Skew > maxSkew {
			maxSkew = -p.Skew
		}
	}
	early := 0
	for _, n := range nodes {
		if n.FirstSeen.IsZero() || len(n.IPs) == 0 {
			continue
		}
		if n.FirstSeen.Before(w.StartAt.Add(-maxSkew - time.Minute)) {
			early++
			r.Soft = append(r.Soft, Finding{
				What: fmt.Sprintf("节点 %s 的首次出现早于真值", displayName(n)),
				Why:  "多数是时钟没对齐，少数是 recovered 的时间被覆写；两种都要能解释",
			})
		}
	}
	r.Metrics["时间越界"] = fmt.Sprint(early)

	// ---- 7. 服务端口：观测到的目的端口必须进节点画像 ----
	//
	// 限定在"真的有人连过的端口"：一台机器 Listen 80/443，整段没人访问 443，
	// 任何被动产品都看不见 443——这不是缺陷，是方法的物理上限。
	portMiss := 0
	srvIPs := make([]string, 0, len(observedSrvPort))
	for ip := range observedSrvPort {
		srvIPs = append(srvIPs, ip)
	}
	sort.Strings(srvIPs)
	for _, ip := range srvIPs {
		key := find(ip)
		if key == "" {
			continue // 节点都没建出来，前面报过
		}
		var got []int
		for _, n := range nodes {
			if n.Key == key {
				got = n.Ports
				break
			}
		}
		ports := make([]int, 0, len(observedSrvPort[ip]))
		for p := range observedSrvPort[ip] {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		for _, p := range ports {
			if !hasPort(got, p) {
				portMiss++
				r.Hard = append(r.Hard, Finding{
					What: fmt.Sprintf("%s 的 %d 端口有流量却没进服务画像", ip, p),
					Why:  "探针看见了这条会话、端口也就在会话里，节点上却没有：角色推断、暴露面统计、弱口令排查全部跟着错",
				})
			}
		}
	}
	r.Metrics["可观测服务端"] = fmt.Sprint(len(observedSrvPort))
	r.Metrics["服务端口漏识"] = fmt.Sprint(portMiss)

	return r
}

func pairKey(a, b string) string { return a + "|" + b }

// ipPair 无向地址对（同一对端，谁先谁后不重要）。
func ipPair(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

// displayName 人类可读的节点名：优先稳定身份，退化到内部 ID。
func displayName(n Node) string {
	if n.NodeKey != "" {
		return n.NodeKey
	}
	return n.Key
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

func hasPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}
