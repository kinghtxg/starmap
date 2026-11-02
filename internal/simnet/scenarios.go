package simnet

import (
	"time"
)

// 场景构造器。
//
// 每个场景只回答一个问题，并且必须能"对着失败解释"：跑红了，是产品的缺陷，
// 还是这个场景本身设计得不合理？所以每个函数上面都写清它想证明什么。

// Clean 干净网络：两台交换机、两个网段、各 10 台设备，无 NAT、无时钟偏移。
//
// 这是**下限**：连干净网络都算错，后面所有场景的结果都不用看了。
// 期望：20 个节点、每条真值链路都有边、每个 IP 只属于一个节点。
func Clean(seed int64, now time.Time) *World {
	w := &World{Name: "clean", StartAt: now.Add(-time.Hour), Span: 20 * time.Minute, Seed: seed}
	segA, segB := "10.1.1.0/24", "10.1.2.0/24"
	w.AddProbe(Probe{ID: "probe-a", Location: "A 栋 3 层", Segments: []string{segA}})
	w.AddProbe(Probe{ID: "probe-b", Location: "B 栋 1 层", Segments: []string{segB}})

	web := []Service{{Port: 80, Proto: "tcp", Product: "nginx/1.18.0"}, {Port: 443, Proto: "tcp", TLS: true}}
	file := []Service{{Port: 445, Proto: "tcp"}}
	ssh := []Service{{Port: 22, Proto: "tcp"}}

	for i := 1; i <= 10; i++ {
		ip := IPIn(segA, i)
		w.AddHost(Host{
			Name: "a" + itoa(i), MAC: MACOf(i), IPs: []string{ip}, Segment: segA,
			Listen: web, Location: "A 栋 3 层 2 柜 12 口",
		})
	}
	for i := 1; i <= 10; i++ {
		ip := IPIn(segB, i)
		w.AddHost(Host{
			Name: "b" + itoa(i), MAC: MACOf(100 + i), IPs: []string{ip}, Segment: segB,
			Listen: file, Location: "B 栋 1 层 1 柜 3 口",
		})
	}
	// 段内 + 跨段流量
	for i := 1; i <= 9; i++ {
		w.AddLink(Link{From: "a" + itoa(i), To: "a" + itoa(i+1), Port: 80, Proto: "tcp", Bytes: 120000})
		w.AddLink(Link{From: "b" + itoa(i), To: "b" + itoa(i+1), Port: 445, Proto: "tcp", Bytes: 90000})
		w.AddLink(Link{From: "a" + itoa(i), To: "b" + itoa(i), Port: 445, Proto: "tcp", Bytes: 60000})
	}
	// 少量 SSH：验证非 Web 端口也能建边
	w.AddLink(Link{From: "a1", To: "b10", Port: ssh[0].Port, Proto: "tcp", Bytes: 8000})
	return w
}

// DualHomed 一机两网：一台设备两个网卡、两个 IP，横跨两个网段。
//
// 政务网里这种设备普遍存在（内外网双网卡、运维跳板机、视频专网互联）。
// 期望：**1 个节点**，两个 IP 都挂在它身上。
// 如果出现 2 个节点，说明按 IP 建节点、没按 MAC 归一——图上立刻多出一台幽灵设备，
// 而且那台"幽灵"往往就是最危险的那台（一机两网是数据外流的典型路径）。
func DualHomed(seed int64, now time.Time) *World {
	w := &World{Name: "dualhomed", StartAt: now.Add(-time.Hour), Span: 15 * time.Minute, Seed: seed}
	segA, segB := "10.2.1.0/24", "10.2.2.0/24"
	w.AddProbe(Probe{ID: "pa", Location: "内网区", Segments: []string{segA}})
	w.AddProbe(Probe{ID: "pb", Location: "外网区", Segments: []string{segB}})

	// 双网卡主机：同一块 MAC 出现在两个网段（真实是两块网卡，但同机；产品应按 MAC 合并）
	w.AddHost(Host{
		Name: "jump", MAC: MACOf(1), IPs: []string{IPIn(segA, 50), IPIn(segB, 50)},
		Segment: segA, Listen: []Service{{Port: 22, Proto: "tcp"}},
		Location: "A 栋 3 层 2 柜 12 口",
	})
	for i := 1; i <= 6; i++ {
		w.AddHost(Host{
			Name: "a" + itoa(i), MAC: MACOf(10 + i), IPs: []string{IPIn(segA, i)},
			Segment: segA, Listen: []Service{{Port: 80, Proto: "tcp", Product: "nginx"}},
			Location: "A 栋 3 层",
		})
	}
	for i := 1; i <= 6; i++ {
		w.AddHost(Host{
			Name: "b" + itoa(i), MAC: MACOf(20 + i), IPs: []string{IPIn(segB, i)},
			Segment: segB, Listen: []Service{{Port: 445, Proto: "tcp"}},
			Location: "B 栋 1 层",
		})
	}
	for i := 1; i <= 6; i++ {
		// 两侧都连跳板机：跳板机的两个 IP 都该出现在同一个节点上
		w.AddLink(Link{From: "a" + itoa(i), To: "jump", Port: 22, Proto: "tcp", Bytes: 50000})
		w.AddLink(Link{From: "jump", To: "b" + itoa(i), Port: 445, Proto: "tcp", Bytes: 40000})
	}
	return w
}

// MultiObserver 同一会话被两个探针同时看到（两处镜像/串接分光）。
//
// 期望：**字节不翻倍**。两个探针报的是同一条会话、同一个五元组，
// 引擎必须按会话增量合并（第二份是"同一会话的又一次报告"，不是新会话）。
//
// 这是最容易被忽略的重复来源：不换端口、不改地址，纯粹"多了一个采集点"。
// 现场的差分交换机镜像、双网卡分流、主备探针同时在线，都会产生它。
func MultiObserver(seed int64, now time.Time) *World {
	w := &World{Name: "multiobserver", StartAt: now.Add(-time.Hour), Span: 10 * time.Minute, Seed: seed}
	seg := "10.3.1.0/24"
	// 两个探针看同一个网段：同一批会话各报一次
	w.AddProbe(Probe{ID: "tap1", Location: "核心镜像口 1", Segments: []string{seg}})
	w.AddProbe(Probe{ID: "tap2", Location: "核心镜像口 2", Segments: []string{seg}})

	for i := 1; i <= 4; i++ {
		w.AddHost(Host{
			Name: "c" + itoa(i), MAC: MACOf(10 + i), IPs: []string{IPIn(seg, 10+i)},
			Segment: seg, Listen: []Service{{Port: 445, Proto: "tcp"}},
		})
	}
	w.AddHost(Host{
		Name: "fs", MAC: MACOf(90), IPs: []string{IPIn(seg, 90)},
		Segment: seg, Listen: []Service{{Port: 445, Proto: "tcp"}},
	})
	for i := 1; i <= 4; i++ {
		w.AddLink(Link{From: "c" + itoa(i), To: "fs", Port: 445, Proto: "tcp", Bytes: 250000})
	}
	return w
}

// NAT 办公网经 SNAT 访问服务器区：同一份载荷在两段各被看见一次。
//
// 期望：
//   - NAT 设备是 **1 个节点**（出口地址 10.3.2.2 与内网侧地址同在它身上）；
//   - 客户端 pc 不被拆；
//   - **字节比 ≈ 2，且这是上限不是缺陷**：源端口被改写、两条会话没有共同字段，
//     被动分析无法关联。产品要做的是把这段重复标注出来，而不是假装总量精确。
//
// 断言里因此用 MaxByteRatio 放宽上限，同时把比值本身留在报告里——哪天有人
// 声称"字节守恒"，这个数字就是打脸的依据。
//
// 这个场景刻意只造"跨 NAT 的同一份载荷"，不掺别的流量：它的用处是把字节比
// 钉在 2.000 上，任何新加的链路都会让这个数字失去解释力。设备身份（网关角色、
// NAT 出口地址归一）由 Egress 场景负责，那里才有真实网络的完整证据链。
func NAT(seed int64, now time.Time) *World {
	w := &World{
		Name: "nat", StartAt: now.Add(-time.Hour), Span: 10 * time.Minute, Seed: seed,
		MaxByteRatio: 2.05, // 两段各一次，上限 2 倍；留 2.5% 余量给缓冲
	}
	segIn, segOut := "10.3.1.0/24", "10.3.2.0/24"
	w.AddProbe(Probe{ID: "pin", Location: "办公区", Segments: []string{segIn}})
	w.AddProbe(Probe{ID: "pout", Location: "服务器区", Segments: []string{segOut}})

	natOut := IPIn(segOut, 2)
	w.AddHost(Host{
		Name: "nat", MAC: MACOf(1), IPs: []string{IPIn(segIn, 1), natOut},
		Segment: segIn, Location: "机房 A 柜 3 口",
	})
	for i := 1; i <= 5; i++ {
		w.AddHost(Host{
			Name: "pc" + itoa(i), MAC: MACOf(10 + i), IPs: []string{IPIn(segIn, 10+i)},
			Segment: segIn,
		})
	}
	w.AddHost(Host{
		Name: "srv", MAC: MACOf(99), IPs: []string{IPIn(segOut, 20)},
		Segment: segOut, Listen: []Service{{Port: 443, Proto: "tcp", TLS: true}},
		Location: "服务器区 B 柜 7 口",
	})
	for i := 1; i <= 5; i++ {
		w.AddLink(Link{
			From: "pc" + itoa(i), To: "srv", Port: 443, Proto: "tcp", Bytes: 200000,
			NATSrc: natOut, // 过了 NAT 之后，服务器区看到的源是出口地址
		})
	}
	return w
}

// ClockSkew 探针时钟不准：一个快 3 分钟、一个慢 2 分钟，共同观测同一批会话。
//
// 期望：节点数与边数不受影响，字节不翻倍。
// 真实风险：先到的报告 LastSeen 比后到报告的 FirstSeen 还晚，五元组复用判据
// 会把同一条会话判成"新连接"从而清零重算——数字来回跳，越跳越大。
func ClockSkew(seed int64, now time.Time) *World {
	w := &World{Name: "skew", StartAt: now.Add(-time.Hour), Span: 10 * time.Minute, Seed: seed}
	seg := "10.4.1.0/24"
	w.AddProbe(Probe{ID: "fast", Location: "东区", Segments: []string{seg}, Skew: 3 * time.Minute})
	w.AddProbe(Probe{ID: "slow", Location: "西区", Segments: []string{seg}, Skew: -2 * time.Minute})

	for i := 1; i <= 4; i++ {
		w.AddHost(Host{
			Name: "s" + itoa(i), MAC: MACOf(i), IPs: []string{IPIn(seg, i)},
			Segment: seg, Listen: []Service{{Port: 445, Proto: "tcp"}},
		})
	}
	for i := 1; i <= 3; i++ {
		w.AddLink(Link{From: "s1", To: "s" + itoa(i+1), Port: 445, Proto: "tcp", Bytes: 300000})
	}
	return w
}

// PartialObservation 探针漏采：30% 会话丢失，只剩单向证据。
//
// 期望：**看见一台设备的一条会话，就该有这台设备**；漏采不该导致整台设备消失。
// 现实对应：探针过载丢包、镜像口带宽不够、采集窗口切分。
func PartialObservation(seed int64, now time.Time) *World {
	w := &World{Name: "partial", StartAt: now.Add(-time.Hour), Span: 30 * time.Minute, Seed: seed}
	seg := "10.5.1.0/24"
	w.AddProbe(Probe{ID: "lossy", Location: "汇聚层", Segments: []string{seg}, Loss: 0.3})

	for i := 1; i <= 12; i++ {
		w.AddHost(Host{
			Name: "p" + itoa(i), MAC: MACOf(i), IPs: []string{IPIn(seg, i)},
			Segment: seg, Listen: []Service{{Port: 80, Proto: "tcp", Product: "Apache"}},
		})
	}
	// 每台都有进有出，保证即使丢 30% 也至少剩一条
	for i := 2; i <= 12; i++ {
		w.AddLink(Link{From: "p" + itoa(i), To: "p1", Port: 80, Proto: "tcp", Bytes: 150000})
		w.AddLink(Link{From: "p1", To: "p" + itoa(i), Port: 80, Proto: "tcp", Bytes: 90000})
	}
	return w
}

// IPConflict 两台设备抢同一个 IP（静态地址配错，政务网高发）。
//
// 期望：**2 个节点**，或至少给出"IP 冲突"的明确告警。
// 最怕的结果是安静地合并成 1 个节点、MAC 被后者覆盖——图上看不出任何异常，
// 而现场是两台机器在抢地址，谁的服务时通时不通，这种问题查一周都查不出来。
func IPConflict(seed int64, now time.Time) *World {
	w := &World{Name: "conflict", StartAt: now.Add(-time.Hour), Span: 10 * time.Minute, Seed: seed}
	seg := "10.6.1.0/24"
	w.AddProbe(Probe{ID: "p", Location: "东区", Segments: []string{seg}})

	conflictIP := IPIn(seg, 30)
	w.AddHost(Host{
		Name: "old", MAC: MACOf(1), IPs: []string{conflictIP},
		Segment: seg, Listen: []Service{{Port: 80, Proto: "tcp", Product: "nginx"}},
	})
	w.AddHost(Host{
		Name: "new", MAC: MACOf(2), IPs: []string{conflictIP},
		Segment: seg, Listen: []Service{{Port: 445, Proto: "tcp"}},
	})
	w.AddHost(Host{Name: "peer", MAC: MACOf(3), IPs: []string{IPIn(seg, 40)}, Segment: seg,
		Listen: []Service{{Port: 8080, Proto: "tcp"}}})

	w.AddLink(Link{From: "peer", To: "old", Port: 80, Proto: "tcp", Bytes: 70000})
	w.AddLink(Link{From: "peer", To: "new", Port: 445, Proto: "tcp", Bytes: 70000})
	// 两台机器各自也要发包：会话只带**源** MAC，只有一方当客户端时，被动侧
	// 拿不到另一方的 MAC，两台抢地址的机器在数据上就是同一个 IP——那不是产品
	// 分辨不出来，是证据里真的没有。现场两台机器都在跑业务，必然各自发包。
	w.AddLink(Link{From: "old", To: "peer", Port: 8080, Proto: "tcp", Bytes: 30000})
	w.AddLink(Link{From: "new", To: "peer", Port: 8080, Proto: "tcp", Bytes: 20000})
	return w
}

// MACDrift MAC 不变、IP 变了（DHCP 续租/换网段）。
//
// 期望：**1 个节点**，两个 IP 都在它身上。这是 IPConflict 的对照组：
// 同样"一个 MAC 两个 IP"，但这次确实是一台设备——产品必须区分这两种情况。
func MACDrift(seed int64, now time.Time) *World {
	w := &World{Name: "drift", StartAt: now.Add(-time.Hour), Span: 20 * time.Minute, Seed: seed}
	seg := "10.7.1.0/24"
	w.AddProbe(Probe{ID: "p", Location: "办公区", Segments: []string{seg}})

	mac := MACOf(7)
	w.AddHost(Host{Name: "laptop", MAC: mac, IPs: []string{IPIn(seg, 11), IPIn(seg, 12)},
		Segment: seg, Listen: []Service{{Port: 445, Proto: "tcp"}}})
	w.AddHost(Host{Name: "srv", MAC: MACOf(8), IPs: []string{IPIn(seg, 20)},
		Segment: seg, Listen: []Service{{Port: 80, Proto: "tcp", Product: "nginx"}}})

	w.AddLink(Link{From: "laptop", To: "srv", Port: 80, Proto: "tcp", Bytes: 100000})
	return w
}

// Egress 一台承担"网关 + NAT + DNS"三合一的出口路由器，办公网通过它访问服务器区与公网。
//
// 这是政务网里最常见的形态：一台设备既是全网默认网关，又是 SNAT 出口，还兼着
// 内部 DNS。它回答了三个问题，缺一条都不算"看见出口"：
//   - **路由器本身**要被发现（1 个节点，带 MAC）；
//   - **NAT 出口地址**要归到同一台设备上（10.8.1.1 与 10.8.9.2 同在它身上，
//     一个是内网口、一个是 NAT 后的出口口），否则出口在图上是一台陌生机器；
//   - **出口方向**要成边（每台主机 → 网关），否则图上是"主机直连公网"，
//     中间那一跳凭空消失——这正是现场排查"谁在上外网"时最先要找的东西。
//
// 三条证据分别来自三个方向，必须都造出来才能验证归一是否正确：
//   - 别人连它（DNS 查询）→ 只能看到它的**内网 IP 在目的端**；
//   - 它自己发包（syslog）→ 才能看到**它的 MAC 当源**；
//   - 它转发公网流量 → 只有**以太网目的 MAC** 是它的 MAC，IP 一个都不出现。
//
// 只有第三条时，产品只能建一个"只有 MAC 的空壳"；只有第一条时，只能建一个
// "没有 MAC 的节点"。两者必须以同一台设备收场，否则图上凭空多一台幽灵。
//
// 注：公网侧出口地址（203.0.113.x）在局域网探针上不可见——报文出了 WAN 口才有它，
// 那时源 MAC 仍是这台路由器。这是部署位置决定的，不是缺陷，故本场景不造 WAN 探针。
func Egress(seed int64, now time.Time) *World {
	w := &World{
		Name: "egress", StartAt: now.Add(-time.Hour), Span: 20 * time.Minute, Seed: seed,
		MaxByteRatio: 1.6, // 办公→服务器区被两段各看一次；上网与日志只有一份，整体略高于 1
	}
	segLan, segSrv, segNet := "10.8.1.0/24", "10.8.9.0/24", "198.51.100.0/24"
	w.AddProbe(Probe{ID: "plan", Location: "A 栋 3 层弱电间", Segments: []string{segLan}})
	w.AddProbe(Probe{ID: "psrv", Location: "核心机房", Segments: []string{segSrv}})

	lanIP, natIP := IPIn(segLan, 1), IPIn(segSrv, 2)
	w.AddHost(Host{
		Name: "edge", MAC: MACOf(200), IPs: []string{lanIP, natIP}, Segment: segLan,
		Listen: []Service{
			{Port: 53, Proto: "tcp"},
			{Port: 22, Proto: "tcp"},
		},
		Location: "A 栋 3 层弱电间 1 柜 1 口",
		Roles:    []string{"gateway"},
	})
	// 日志服务器：路由器主动给它的流量，是"路由器自己的 MAC"唯一的来源
	w.AddHost(Host{
		Name: "log", MAC: MACOf(210), IPs: []string{IPIn(segLan, 250)}, Segment: segLan,
		Listen: []Service{{Port: 514, Proto: "udp"}}, Location: "A 栋 3 层 2 柜 5 口",
	})
	w.AddHost(Host{
		Name: "app", MAC: MACOf(220), IPs: []string{IPIn(segSrv, 20)}, Segment: segSrv,
		Listen:   []Service{{Port: 443, Proto: "tcp", TLS: true}},
		Location: "核心机房 B 柜 8 口",
	})
	// 公网目标：只有"目的在内网之外"才能证明谁在给全网做首跳转发
	w.AddHost(Host{
		Name: "pubapi", IPs: []string{"198.51.100.20"}, Segment: segNet,
		Listen: []Service{{Port: 443, Proto: "tcp", TLS: true}},
	})

	for i := 1; i <= 6; i++ {
		name := "pc" + itoa(i)
		w.AddHost(Host{
			Name: name, MAC: MACOf(10 + i), IPs: []string{IPIn(segLan, 10+i)},
			Segment: segLan, Location: "A 栋 3 层",
		})
		// 全网都用网关当 DNS：这是"网关的内网 IP"被看见的唯一途径
		w.AddLink(Link{From: name, To: "edge", Port: 53, Proto: "tcp", Bytes: 6000, ViaMAC: MACOf(200)})
		// 经 NAT 访问服务器区：两段各被看见一次，出口地址归到同一台设备
		w.AddLink(Link{
			From: name, To: "app", Port: 443, Proto: "tcp", Bytes: 100000,
			NATSrc: natIP, ViaMAC: MACOf(200),
		})
		// 上公网：目的在内网之外，以太网目的 MAC 就是首跳网关
		w.AddLink(Link{From: name, To: "pubapi", Port: 443, Proto: "tcp", Bytes: 120000, ViaMAC: MACOf(200)})
	}
	// 路由器自己外发日志：源 MAC 是自己，这是把它从"空壳"变成"有名有姓"的关键一条
	w.AddLink(Link{From: "edge", To: "log", Port: 514, Proto: "udp", Bytes: 4000})
	return w
}

// Proxy 七层代理（nginx/HAProxy/SLB）：真实客户端只存在于 X-Forwarded-For 里。
//
// 期望：
//   - 代理本身是 **1 个节点**，带上代理角色（它是全网流量的必经点，不能显示"未识别"）；
//   - 每台真实客户端都在图上，带 xff-client 标记，并与代理之间有关系边；
//   - 字节不翻倍：这里只造服务端侧那一条会话（客户端→代理是另一条五元组，
//     造出来会把 NAT 场景已经测过的"重复计入"再混进来，掩盖真正的判据）。
//
// 现场对应：政务云里业务系统前面挂一台 WAF/负载均衡，服务端的访问日志里
// 源地址永远是 WAF 的地址。不还原 XFF，图上是"一台机器访问了所有业务"，
// 而真正的客户端（可能是被攻陷的终端）一台都看不见。
func Proxy(seed int64, now time.Time) *World {
	w := &World{Name: "proxy", StartAt: now.Add(-time.Hour), Span: 15 * time.Minute, Seed: seed}
	segOffice, segApp := "10.9.1.0/24", "10.9.2.0/24"
	w.AddProbe(Probe{ID: "poffice", Location: "办公区", Segments: []string{segOffice}})
	w.AddProbe(Probe{ID: "papp", Location: "应用区", Segments: []string{segApp}})

	w.AddHost(Host{
		Name: "waf", MAC: MACOf(150), IPs: []string{IPIn(segApp, 10)}, Segment: segApp,
		Listen:   []Service{{Port: 80, Proto: "tcp", Product: "nginx/1.20.1"}},
		Location: "应用区 DMZ 1 柜 2 口",
		Roles:    []string{"proxy"}, Labels: []string{"xff-proxy"},
	})
	w.AddHost(Host{
		Name: "app", MAC: MACOf(160), IPs: []string{IPIn(segApp, 20)}, Segment: segApp,
		Listen:   []Service{{Port: 80, Proto: "tcp", Product: "Tomcat"}},
		Location: "应用区 2 柜 5 口",
	})
	for i := 1; i <= 3; i++ {
		w.AddHost(Host{
			Name: "c" + itoa(i), MAC: MACOf(20 + i), IPs: []string{IPIn(segOffice, 10+i)},
			Segment:  segOffice,
			Location: "办公区",
			Labels:   []string{"xff-client"},
		})
		w.AddLink(Link{From: "c" + itoa(i), To: "app", Port: 80, Proto: "tcp", Bytes: 150000, ViaProxy: "waf"})
	}
	return w
}

// All 返回全部场景（顺序固定，便于回归比对）。
func All(seed int64, now time.Time) []*World {
	return []*World{
		Clean(seed, now),
		DualHomed(seed, now),
		MultiObserver(seed, now),
		NAT(seed, now),
		ClockSkew(seed, now),
		PartialObservation(seed, now),
		IPConflict(seed, now),
		MACDrift(seed, now),
		Egress(seed, now),
		Proxy(seed, now),
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
