// Package simnet 生成"带真值的内网世界"，用于在没有真实网络时校准星图。
//
// 为什么需要它：内网产品最大的困难是**没有 ground truth**——你不知道那台设备
// 到底开了几个端口、连了几台机器。没有真值就谈不上"准确率"，只能靠肉眼觉得
// "看起来对"。这个包把真值**造**出来：世界是我们生成的，所以每台设备、
// 每条链路、谁在什么位置、谁被哪个探针看到，全都是已知的。
//
// 三条设计约束，缺一条这套东西就会退化成"自己测自己"：
//
//  1. **真值与观测分离**。World 是客观事实；Sessions() 产出的是"探针各自看到了
//     什么"。两者之间的差异（漏采、丢包、看不到 MAC、时钟偏移）才是被测对象。
//  2. **确定性**。同一个 seed 必须产出逐字节相同的世界与会话流，否则无法进 CI
//     做回归（今天红明天绿的东西没人会去修）。
//  3. **只造会被误判的东西**。干净网络谁都能处理；真正打垮产品的是 NAT、
//     多观察者、跨三层看不到 MAC、时钟偏移、IP 冲突。这些在 World 里都必须能表达。
package simnet

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"starmap/internal/model"
)

// Service 一台设备真实监听的服务。
//
// Port 用真实世界常见的端口，不要自造：星图的端口→服务名映射、角色推断、
// 站点识别都基于真实端口。用 65001 之类测出来的"通"，在真实网络里毫无意义。
type Service struct {
	Port    uint16
	Proto   string
	Product string // 指纹用（nginx/1.18.0、群晖 DSM、海康 Web）
	TLS     bool
}

// Host 一台真实存在的设备。
//
// MAC 为空的设备（如纯路由转发、或跨网段看不到二层）也是合法的：真值里允许
// "只知道 IP 不知道 MAC"，产品必须能处理这种残缺，而不是造一个假 MAC 补上。
type Host struct {
	Name    string
	MAC     string
	IPs     []string
	Listen  []Service
	Segment string // 所在网段，如 10.1.1.0/24
	// Location 物理接入位置（弱电间/机柜/端口）。星图目前没有这个能力，
	// 但真值里必须留着——它是"这台机器在哪"的唯一答案，也是下一步要补的短板。
	Location string
	// Roles 期望被识别出的角色（gateway / nas / printer / proxy …），空表示不做断言。
	Roles []string
}

// Link 一条真实发生过的通信（有向：From 是客户端）。
type Link struct {
	From  string
	To    string
	Port  uint16
	Proto string
	Bytes int64
	// NATSrc 源地址在**目的网段侧**的呈现（SNAT 转换后的出口地址），空表示不变。
	//
	// 为什么必须能在真值里表达：办公网经 NAT 访问服务器区时，内网探针看到的是
	// (10.3.1.11 → 10.3.2.20:443)，机房探针看到的是 (10.3.2.2 → 10.3.2.20:443)——
	// 源端口也被改写，两条会话没有任何共同字段。任何被动产品都无法把它们关联
	// 成一条，字节必然被算两次。这不是实现缺陷，是方法的上限；真值必须能生成
	// 这种情形，产品才知道自己错在哪、该在哪里标注"跨 NAT 区间存在重复"。
	NATSrc string
	// Port 是服务端端口；客户端临时端口由生成器分配，同一会话对多个观察者必须一致，
	// 否则同一个会话会被当成两条，测出来的"重复计数"其实是自己造的假象。
}

// Probe 一个观测点。
//
// Segments 决定它能看见什么：只在一个网段内的探针，看得到该网段的二层信息
// （源 MAC）；跨网段转发后的流量，源 MAC 已经被网关替换，探针只拿得到 IP。
// 这个差异是真实网络里"同一台设备出现两次"的头号成因，必须能模拟。
type Probe struct {
	ID       string
	Location string
	Segments []string
	// Skew 时钟偏移：探针自己的时钟比服务器快/慢多少。
	// 真实网络里 NTP 没同步的内网随处可见，而星图的五元组复用判据、时间线
	// 都直接吃这个时间戳。
	Skew time.Duration
	// Loss 漏采率（0~1）：探针过载/丢包时只看到一部分会话。
	Loss float64
}

// World 一个有真值的世界。
type World struct {
	Name    string
	Hosts   []Host
	Links   []Link
	Probes  []Probe
	StartAt time.Time
	// Span 所有链路发生的时间跨度，用于生成 FirstSeen/LastSeen。
	Span time.Duration
	Seed int64
	// MaxByteRatio 允许的"图上字节 / 观测字节"上限，0 表示默认 1.02（要求严格守恒）。
	//
	// 只有 NAT 场景会把它调高：同一份载荷在两段各被看见一次，源端口被改写、
	// 两条会话没有共同字段，被动分析无法关联。这是方法的物理上限，产品该做的是
	// **标注重复**而不是假装准确——所以这里放宽上限，同时保留这个数字进报告。
	MaxByteRatio float64
}

// Host 按名字取设备（找不到返回 nil）。
func (w *World) Host(name string) *Host {
	for i := range w.Hosts {
		if w.Hosts[i].Name == name {
			return &w.Hosts[i]
		}
	}
	return nil
}

// HostNames 返回所有设备名（排序后，便于稳定输出）。
func (w *World) HostNames() []string {
	out := make([]string, 0, len(w.Hosts))
	for i := range w.Hosts {
		out = append(out, w.Hosts[i].Name)
	}
	sort.Strings(out)
	return out
}

// Sessions 把世界"烧"成探针上报的会话流。
//
// 这一步是整个包的核心：它决定每个探针**看到**什么，而不是真相是什么。
// 同一台设备在 A 探针眼里有 MAC、在 B 探针眼里只有 IP，最终必须合并成同一个
// 节点——合并失败就是产品缺陷，合并成功也不该靠运气。
func (w *World) Sessions() []model.Session {
	rnd := rand.New(rand.NewSource(w.Seed))
	out := make([]model.Session, 0, len(w.Links)*2)
	// 会话起点在时间窗内均匀铺开，让 first_seen/last_seen 有先后关系
	span := w.Span
	if span <= 0 {
		span = time.Minute
	}
	// 客户端临时端口：一条链路一个，跨观察者复用（同一个会话）
	nextPort := uint16(30000) + uint16(rnd.Intn(2000))

	for _, l := range w.Links {
		src, dst := w.Host(l.From), w.Host(l.To)
		if src == nil || dst == nil || len(src.IPs) == 0 || len(dst.IPs) == 0 {
			continue
		}
		ephemeral := nextPort
		nextPort++
		if nextPort > 60000 {
			nextPort = 30000
		}
		start := w.StartAt.Add(time.Duration(rnd.Int63n(int64(span))))

		// 谁能看到这条会话：源网段或目的网段的探针
		for _, p := range w.Probes {
			if !p.sees(src.Segment) && !p.sees(dst.Segment) {
				continue
			}
			if p.Loss > 0 && rnd.Float64() < p.Loss {
				continue // 探针漏采
			}
			// 二层可见性：只有与源同网段的探针看得到源 MAC。
			// 三层可见性：跨段时源地址可能已被 NAT 改写，探针看到的是出口地址。
			mac, srcIP := "", src.IPs[0]
			if p.sees(src.Segment) {
				mac = src.MAC
			} else if l.NATSrc != "" {
				srcIP = l.NATSrc
			}
			s := model.Session{
				FiveTuple: model.FiveTuple{
					SrcIP: srcIP, DstIP: dst.IPs[0],
					SrcPort: ephemeral, DstPort: l.Port, Proto: l.Proto,
				},
				MAC:       mac,
				FirstSeen: start.Add(p.Skew),
				LastSeen:  start.Add(p.Skew).Add(2 * time.Minute),
				BytesUp:   l.Bytes / 3,
				BytesDown: l.Bytes - l.Bytes/3,
				Packets:   40,
				Location:  p.Location,
				ProbeID:   p.ID,
			}
			if svc := dst.service(l.Port); svc != nil {
				// 明文 HTTP 才看得到 Server 头；TLS 流量拿不到，这一点必须如实模拟
				if !svc.TLS && svc.Product != "" {
					s.HTTPServer = svc.Product
				}
				if svc.TLS && svc.Product != "" {
					// TLS 场景下探针只能看到 SNI / 证书，交给 CN 字段不合适，
					// 这里留空：宁可少给证据，也不要给一个真实网络里拿不到的证据。
					s.SNI = ""
				}
			}
			out = append(out, s)
		}
	}
	return out
}

// 期望的节点数：每台真机一个节点（不聚合时）。
func (w *World) ExpectedNodes() int { return len(w.Hosts) }

func (p Probe) sees(segment string) bool {
	for _, s := range p.Segments {
		if s == segment || s == "*" {
			return true
		}
	}
	return false
}

func (h *Host) service(port uint16) *Service {
	for i := range h.Listen {
		if h.Listen[i].Port == port {
			return &h.Listen[i]
		}
	}
	return nil
}

// AddHost 往世界里加一台设备（场景构造器用）。
func (w *World) AddHost(h Host) { w.Hosts = append(w.Hosts, h) }

// AddLink 加一条真实链路。
func (w *World) AddLink(l Link) { w.Links = append(w.Links, l) }

// AddProbe 加一个观测点。
func (w *World) AddProbe(p Probe) { w.Probes = append(w.Probes, p) }

// MACOf 生成一个稳定的、不重复的 MAC（本地管理地址段，避免与真实厂商前缀冲突）。
func MACOf(i int) string {
	return fmt.Sprintf("02:00:00:%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

// IPIn 返回网段内第 n 个可用地址（网段形如 10.1.1.0/24，n 从 1 开始）。
//
// 取模是为了容忍场景里写大数字，但必须 (n-1)%254+1 —— 早先写成 n%254+1，
// 传 1 得到的是 .2，所有场景的地址整体偏移一位。地址本身仍唯一，不会撞车，
// 但真值报告里"第 N 台主机"和实际地址对不上，人工核对时极易看错。
func IPIn(segment string, n int) string {
	var a, b, c int
	if _, err := fmt.Sscanf(segment, "%d.%d.%d.", &a, &b, &c); err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, (n-1)%254+1)
}
