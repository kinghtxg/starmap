// Package parser 报文解析：五元组/MAC/TTL/会话聚合/TLS ClientHello(SNI)/JA3/JA4/HTTP Host/
// 长连接与心跳特征判定。输出 model.Session，供 topology 与 detect 模块消费（SPEC §2 数据流）。
package parser

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"starmap/internal/model"
)

// PacketInfo 单个报文解析出的元信息（ingest 层交给 parser 的输入）。
type PacketInfo struct {
	Timestamp time.Time
	SrcMAC    string
	DstMAC    string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Proto     string // tcp|udp
	TTL       int
	Payload   []byte // 传输层载荷
	Length    int    // 报文总长度
	TCPFlags  uint8  // SYN/ACK/FIN/RST 等（layers.TCP 标志位组合）

	// 预解析会话元数据（探针上报已带 SNI/JA3/JA4 等，无需再从 Payload 反解）。
	// 修复：探针 flows 合成报文时此前丢弃这些字段，导致 frp/clash/reverse_proxy 规则失效。
	SNI                 string
	HTTPHost            string
	JA3                 string
	JA4                 string
	IsLongConn          bool
	HeartbeatIntervalMs int64
	// XFF / XRealIP 七层转发链（V1.8）。探针若已解析可直接上报，优先级高于载荷反解。
	XFF     []string
	XRealIP string
	// Location 来源探针的位置（V1.3：按探针位置归纳拓扑）。
	Location string
}

// ParsePacket 从 gopacket.Packet 提取 PacketInfo；非 IP/TCP/UDP 报文返回 nil。
func ParsePacket(pkt gopacket.Packet) *PacketInfo {
	info := &PacketInfo{Timestamp: pkt.Metadata().Timestamp}
	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		e := eth.(*layers.Ethernet)
		info.SrcMAC = e.SrcMAC.String()
		info.DstMAC = e.DstMAC.String()
	}
	var netOK bool
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.TTL = int(ip.TTL)
		info.Length = int(ip.Length)
		netOK = true
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.TTL = int(ip.HopLimit)
		info.Length = int(ip.Length)
		netOK = true
	}
	if !netOK {
		return nil
	}
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		info.Proto = "tcp"
		info.SrcPort = uint16(t.SrcPort)
		info.DstPort = uint16(t.DstPort)
		info.Payload = t.Payload
		if info.Length == 0 {
			info.Length = len(t.Payload)
		}
		if t.SYN {
			info.TCPFlags |= 0x02
		}
		if t.ACK {
			info.TCPFlags |= 0x10
		}
		if t.FIN {
			info.TCPFlags |= 0x01
		}
		if t.RST {
			info.TCPFlags |= 0x04
		}
		return info
	}
	if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		info.Proto = "udp"
		info.SrcPort = uint16(u.SrcPort)
		info.DstPort = uint16(u.DstPort)
		info.Payload = u.Payload
		return info
	}
	return nil
}

// ---------- TLS ClientHello 解析 ----------

// ClientHelloInfo TLS ClientHello 解析结果。
type ClientHelloInfo struct {
	Version      uint16
	Ciphers      []uint16
	Extensions   []uint16
	Curves       []uint16
	PointFormats []byte
	SigAlgs      []uint16
	SNI          string
	ALPN         string
}

// ParseClientHello 解析 TLS ClientHello 原始报文（从 TLS record 层开始）。
// 非 ClientHello 返回 nil。
func ParseClientHello(data []byte) *ClientHelloInfo {
	// TLS Record: type(1)=0x16, version(2), length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	body := data[5:]
	if recLen > len(body) {
		recLen = len(body)
	}
	body = body[:recLen]
	// Handshake: type(1)=0x01 client_hello, length(3)
	if len(body) < 4 || body[0] != 0x01 {
		return nil
	}
	hs := body[4:]
	if len(hs) < 34 {
		return nil
	}
	info := &ClientHelloInfo{}
	info.Version = binary.BigEndian.Uint16(hs[0:2])
	rest := hs[34:] // 跳过 version(2)+random(32)
	if len(rest) < 1 {
		return nil
	}
	sidLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < sidLen+2 {
		return nil
	}
	rest = rest[sidLen:]
	csLen := int(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if len(rest) < csLen+1 {
		return nil
	}
	for i := 0; i+1 < csLen; i += 2 {
		info.Ciphers = append(info.Ciphers, binary.BigEndian.Uint16(rest[i:i+2]))
	}
	rest = rest[csLen:]
	compLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < compLen+2 {
		return info // 无扩展
	}
	rest = rest[compLen:]
	extTotal := int(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if extTotal > len(rest) {
		extTotal = len(rest)
	}
	ext := rest[:extTotal]
	for len(ext) >= 4 {
		et := binary.BigEndian.Uint16(ext[0:2])
		el := int(binary.BigEndian.Uint16(ext[2:4]))
		ed := ext[4:]
		if el > len(ed) {
			break
		}
		info.Extensions = append(info.Extensions, et)
		parseExtension(info, et, ed[:el])
		ext = ed[el:]
	}
	return info
}

// parseExtension 解析关键扩展：SNI(0)、supported_groups(10)、ec_point_formats(11)、ALPN(16)、signature_algorithms(13)。
func parseExtension(info *ClientHelloInfo, et uint16, d []byte) {
	switch et {
	case 0x0000: // server_name
		if len(d) < 5 {
			return
		}
		listLen := int(binary.BigEndian.Uint16(d[0:2]))
		if listLen+2 > len(d) || len(d) < 5 {
			return
		}
		// 第一个条目：type(1) + len(2) + name
		nameLen := int(binary.BigEndian.Uint16(d[3:5]))
		if 5+nameLen <= len(d) {
			info.SNI = string(d[5 : 5+nameLen])
		}
	case 0x000a: // supported_groups
		if len(d) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(d[0:2]))
		for i := 0; i+3 < n+2 && 2+i+1 < len(d); i += 2 {
			info.Curves = append(info.Curves, binary.BigEndian.Uint16(d[2+i:2+i+2]))
		}
	case 0x000b: // ec_point_formats
		if len(d) < 1 {
			return
		}
		n := int(d[0])
		for i := 0; i < n && 1+i < len(d); i++ {
			info.PointFormats = append(info.PointFormats, d[1+i])
		}
	case 0x000d: // signature_algorithms
		if len(d) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(d[0:2]))
		for i := 0; i+3 < n+2 && 2+i+1 < len(d); i += 2 {
			info.SigAlgs = append(info.SigAlgs, binary.BigEndian.Uint16(d[2+i:2+i+2]))
		}
	case 0x0010: // ALPN
		if len(d) < 3 {
			return
		}
		nameLen := int(d[2])
		if 3+nameLen <= len(d) {
			info.ALPN = string(d[3 : 3+nameLen])
		}
	}
}

// ---------- HTTP Host 提取 ----------

// ExtractHTTPHost 从 HTTP 请求载荷中提取 Host 头；非 HTTP 请求返回空串。
func ExtractHTTPHost(payload []byte) string {
	if len(payload) < 16 {
		return ""
	}
	// 快速判断常见 HTTP 方法，避免误解析
	prefixes := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	ok := false
	for _, p := range prefixes {
		if bytes.HasPrefix(payload, []byte(p)) {
			ok = true
			break
		}
	}
	if !ok {
		return ""
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return ""
	}
	return req.Host
}

// ---------- 会话聚合 ----------

// maxPacketSamples 单会话心跳采样上限。
// 心跳判定只需最近若干个小包（≥3 个间隔即可），全量累积在长连接上会无界增长。
const maxPacketSamples = 64

// 会话表容量与存活期默认值（V1.0 定版）。
const (
	defaultMaxSessions   = 200000
	defaultIdleSeconds   = 300   // 静默 5 分钟即回收
	defaultMaxAgeSeconds = 21600 // 单会话最长存活 6 小时（防不关连接撑爆）
	closedGraceSeconds   = 30    // 已 FIN/RST 的会话再留 30 秒收尾
)

// sessionState 内存会话状态
type sessionState struct {
	session    *model.Session
	isClient   func(srcIP string, srcPort uint16) bool // 判断方向
	packetLens []int                                   // 小包长度序列（心跳判定）
	packetGaps []int64                                 // 相邻小包间隔 ms
	lastTs     time.Time
	helloDone  bool
	hostDone   bool
	fwdDone    bool // 已解析过转发头（XFF/X-Real-IP），只解析首批 HTTP 载荷
	dirty      bool // 自上次抽取以来有更新（增量下发）
	emitted    bool // 已被抽出过（用于判定首次落库）
	// 回收判定用「摄入墙钟」，不是报文时间戳。
	// 导入昨天的 PCAP 时，报文时间早已过期，若按报文时间淘汰会把整批历史数据当场丢掉。
	bornAt time.Time
	seenAt time.Time
}

// Aggregator 内存会话表：按五元组聚合 PacketInfo 为 model.Session。
//
// 容量治理（V1.0）：会话表不再是"只进不出"的黑洞。
//   - 只有变脏（dirty）的会话会在 Drain 时被抽出，避免每轮把全表重放给引擎；
//   - 已关闭超 closedGraceSeconds、静默超 IdleSeconds、存活超 MaxAgeSeconds 的会话被回收；
//   - 表大小达到 MaxSessions 时先回收一轮可回收会话，仍超限则丢弃新会话并累计 Dropped。
//
// 被动分析面对的是真实网络，一个持续抓包的实例如果只增不减，几小时内就会 OOM。
type Aggregator struct {
	mu       sync.Mutex
	sessions map[string]*sessionState
	// 判定参数（来自 SystemConfig）
	LongConnSeconds   int64
	HeartbeatMaxBytes int
	// 容量治理
	MaxSessions   int
	IdleSeconds   int64
	MaxAgeSeconds int64
	// NowFunc 摄入侧时钟，默认 time.Now。测试注入可控时钟以模拟时间推进；
	// 生产环境不要改，否则会话回收会与真实时间脱节。
	NowFunc      func() time.Time
	dropped      int64 // 因容量上限被丢弃的新会话数
	evictedTotal int64 // 累计回收会话数
}

// now 返回摄入时钟（未注入则用真实时钟）。
func (a *Aggregator) now() time.Time {
	if a.NowFunc != nil {
		return a.NowFunc()
	}
	return time.Now()
}

// AggregatorStats 会话表运行时指标（/api/stats 暴露）。
type AggregatorStats struct {
	Active      int   `json:"active"`
	MaxSessions int   `json:"max_sessions"`
	Dropped     int64 `json:"dropped"`
	Evicted     int64 `json:"evicted"`
}

// SessionEntry 一次增量抽取中的单条会话。
type SessionEntry struct {
	Session model.Session
	// First 表示该五元组首次被抽出。调用方据此决定是否落库，
	// 从而把「会话去重」这件事收敛到聚合器内部，外部不再需要维护一张无界增长的去重表。
	First bool
}

// DrainResult 一轮增量抽取结果。
type DrainResult struct {
	// Entries 自上次抽取以来有更新的会话（增量，不是全量）。
	Entries []SessionEntry
	// Evicted 本轮被回收的五元组 key。
	Evicted []string
	// Active 抽取后的会话总数。
	Active int
	// Dropped 累计因容量上限丢弃的新会话数。
	Dropped int64
}

// Sessions 只取会话列表的便捷方法。
func (r DrainResult) Sessions() []model.Session {
	out := make([]model.Session, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, e.Session)
	}
	return out
}

// SetLimits 设置会话表容量治理参数；非正数表示使用默认值。
func (a *Aggregator) SetLimits(maxSessions int, idleSeconds, maxAgeSeconds int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maxSessions > 0 {
		a.MaxSessions = maxSessions
	}
	if idleSeconds > 0 {
		a.IdleSeconds = idleSeconds
	}
	if maxAgeSeconds > 0 {
		a.MaxAgeSeconds = maxAgeSeconds
	}
}

// NewAggregator 创建会话聚合器。
func NewAggregator(longConnSeconds int64, heartbeatMaxBytes int) *Aggregator {
	if longConnSeconds <= 0 {
		longConnSeconds = 3600
	}
	if heartbeatMaxBytes <= 0 {
		heartbeatMaxBytes = 64
	}
	return &Aggregator{
		sessions:          make(map[string]*sessionState),
		LongConnSeconds:   longConnSeconds,
		HeartbeatMaxBytes: heartbeatMaxBytes,
		MaxSessions:       defaultMaxSessions,
		IdleSeconds:       defaultIdleSeconds,
		MaxAgeSeconds:     defaultMaxAgeSeconds,
	}
}

// Ingest 喂入一个报文，更新会话状态。
func (a *Aggregator) Ingest(p *PacketInfo) {
	if p == nil || p.SrcIP == "" {
		return
	}
	ft := model.FiveTuple{SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort, Proto: p.Proto}
	key := ft.Key()
	now := a.now() // 摄入墙钟：仅用于会话回收，不参与任何业务判定

	a.mu.Lock()
	defer a.mu.Unlock()

	st, ok := a.sessions[key]
	if !ok {
		// 容量上限：先回收一轮过期会话；仍有压力则丢弃新会话（只丢弃，不挤占已有分析结果）。
		if a.MaxSessions > 0 && len(a.sessions) >= a.MaxSessions {
			a.evictLocked(now)
			if len(a.sessions) >= a.MaxSessions {
				a.dropped++
				return
			}
		}
		ses := &model.Session{
			FiveTuple: ft,
			MAC:       p.SrcMAC,
			StartTTL:  p.TTL,
			FirstSeen: p.Timestamp,
			LastSeen:  p.Timestamp,
			Location:  p.Location,
		}
		st = &sessionState{session: ses, dirty: true, bornAt: now, seenAt: now}
		// 以"发起方端口 > 对端端口"作为客户端方向的粗略启发（临时端口）
		base := st.session
		st.isClient = func(srcIP string, srcPort uint16) bool {
			return srcIP == base.FiveTuple.SrcIP && srcPort == base.FiveTuple.SrcPort
		}
		a.sessions[key] = st
	} else if ses := st.session; ses.Location == "" && p.Location != "" {
		ses.Location = p.Location
		st.dirty = true
	}

	ses := st.session
	st.dirty = true
	st.seenAt = now
	ses.LastSeen = p.Timestamp
	ses.Packets++
	if st.isClient(p.SrcIP, p.SrcPort) {
		ses.BytesUp += int64(p.Length)
		if p.DstMAC != "" {
			ses.DstMAC = p.DstMAC // 客户端方向的目的 MAC：首跳网关推断（NAT 修复）
		}
	} else {
		ses.BytesDown += int64(p.Length)
	}

	// 预解析元数据直接采用（探针上报，优先级高于 Payload 反解）
	if p.SNI != "" {
		ses.SNI = p.SNI
		st.helloDone = true
	}
	if p.HTTPHost != "" {
		ses.HTTPHost = p.HTTPHost
		st.hostDone = true
	}
	if p.JA3 != "" {
		ses.JA3 = p.JA3
		st.helloDone = true
	}
	if p.JA4 != "" {
		ses.JA4 = p.JA4
		st.helloDone = true
	}
	if p.IsLongConn {
		ses.IsLongConn = true
	}
	if p.HeartbeatIntervalMs > 0 {
		ses.HeartbeatIntervalMs = p.HeartbeatIntervalMs
	}

	// 关闭判定：FIN 或 RST
	if p.TCPFlags&0x01 != 0 || p.TCPFlags&0x04 != 0 {
		ses.Closed = true
	}

	// 心跳特征采样：仅记录小载荷包（预解析心跳已带值则不再采样）
	// 采样窗口封顶 maxPacketSamples：心跳是"最近行为"，早期样本对判定无增益，全量累积会无界吃内存。
	if ses.HeartbeatIntervalMs == 0 && p.Length > 0 && p.Length <= a.HeartbeatMaxBytes {
		if !st.lastTs.IsZero() && len(st.packetGaps) < maxPacketSamples {
			st.packetGaps = append(st.packetGaps, p.Timestamp.Sub(st.lastTs).Milliseconds())
		}
		if len(st.packetLens) < maxPacketSamples {
			st.packetLens = append(st.packetLens, p.Length)
		}
		st.lastTs = p.Timestamp
	}

	// TLS ClientHello：仅在 TCP 且未解析过时尝试（预解析元数据优先）
	if p.Proto == "tcp" && !st.helloDone && len(p.Payload) > 5 && p.Payload[0] == 0x16 {
		if ch := ParseClientHello(p.Payload); ch != nil {
			st.helloDone = true
			ses.SNI = ch.SNI
			ses.JA3 = JA3(ch.Version, ch.Ciphers, ch.Extensions, ch.Curves, ch.PointFormats)
			ses.JA4 = JA4("t", ch.Version, ch.SNI != "", ch.Ciphers, ch.Extensions, ch.SigAlgs, ch.ALPN)
		}
	}
	// HTTP Host
	if p.Proto == "tcp" && !st.hostDone && ses.HTTPHost == "" && len(p.Payload) > 0 {
		if host := ExtractHTTPHost(p.Payload); host != "" {
			st.hostDone = true
			ses.HTTPHost = host
		}
	}
	// 七层转发链（V1.8）：探针已解析的直接采用，否则从 HTTP 载荷反解。
	// XFF 只在请求方向出现，解析一次即可（keep-alive 后续请求不必重复解）。
	if len(p.XFF) > 0 || p.XRealIP != "" {
		applyForwarded(ses, p.XFF, p.XRealIP)
		st.fwdDone = true
	} else if p.Proto == "tcp" && !st.fwdDone && len(p.Payload) > 0 {
		if fi := ExtractForwarded(p.Payload); fi.RealClient != "" {
			st.fwdDone = true
			applyForwarded(ses, fi.XFF, fi.XRealIP)
			if ses.HTTPHost == "" && fi.Host != "" {
				ses.HTTPHost = fi.Host
				st.hostDone = true
			}
		}
	}

	// 长连接判定
	if ses.LastSeen.Sub(ses.FirstSeen).Seconds() >= float64(a.LongConnSeconds) {
		ses.IsLongConn = true
	}
}

// applyForwarded 把转发链写入会话（V1.8）。
// XFF[0] 是最原始客户端；X-Real-IP 作为兜底；ProxyHops = 链长，即请求穿过的代理层数。
func applyForwarded(ses *model.Session, xff []string, xreal string) {
	if ses == nil {
		return
	}
	if len(xff) > 0 {
		ses.XFF = append([]string(nil), xff...)
		ses.RealClientIP = xff[0]
		ses.ProxyHops = len(xff)
	}
	if xreal != "" {
		if ses.XRealIP == "" {
			ses.XRealIP = xreal
		}
		if ses.RealClientIP == "" {
			ses.RealClientIP = xreal
			ses.ProxyHops = 1
		}
	}
}

// Finalize 兼容包装：抽取增量会话并回收过期会话（时间基准取当前时钟）。
//
// 注意（V1.0 变更）：返回值语义由「全部会话」改为「自上次抽取以来有更新的会话」。
// 需要全量视图请用 Sessions()。带时间基准的调用方应直接用 Drain(now)。
func (a *Aggregator) Finalize() []model.Session {
	return a.Drain(a.now()).Sessions()
}

// DrainNow 用摄入时钟做一轮增量抽取（生产路径统一走这里）。
func (a *Aggregator) DrainNow() DrainResult { return a.Drain(a.now()) }

// Drain 抽取增量会话并回收过期会话。
//
// now 传报文时间或当前时钟均可，但必须单调不回退：回收判定依赖 now 与 FirstSeen/LastSeen 的差。
// 返回的 Entries 只含 dirty 会话，引擎侧因此不必每轮重放全表（O(变更) 而不是 O(全表)）。
func (a *Aggregator) Drain(now time.Time) DrainResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	evicted := a.evictLocked(now)

	out := make([]SessionEntry, 0, len(a.sessions))
	for _, st := range a.sessions {
		if !st.dirty {
			continue
		}
		st.dirty = false
		ses := st.session
		if len(st.packetGaps) >= 3 {
			// 周期性心跳判定：间隔中位数稳健，允许少量离群（如 FIN 收尾包）。
			// ≥80% 的间隔落在 [0.5×中位数, 1.5×中位数] 区间 → 判定为心跳。
			sorted := append([]int64(nil), st.packetGaps...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			med := sorted[len(sorted)/2]
			if med > 0 {
				hit := 0
				for _, g := range sorted {
					if g*2 >= med && g*2 <= med*3 {
						hit++
					}
				}
				if hit*5 >= len(sorted)*4 {
					ses.HeartbeatIntervalMs = med
				}
			}
		}
		entry := SessionEntry{Session: *ses, First: !st.emitted}
		st.emitted = true
		out = append(out, entry)
	}
	return DrainResult{
		Entries: out,
		Evicted: evicted,
		Active:  len(a.sessions),
		Dropped: a.dropped,
	}
}

// evictLocked 回收过期会话，返回被回收的五元组 key。调用方需持有 a.mu。
//
// 判定基准是「摄入墙钟」（bornAt/seenAt），不是报文时间戳 —— 否则导入历史 PCAP
// 时整批数据会在第一次 Drain 就被当成"静默超时"清空。
//
// 三类可回收：
//  1. 已 FIN/RST 且静默超过 closedGraceSeconds —— 收尾窗口已过；
//  2. 静默超过 IdleSeconds —— 对端不再发包，会话不再有分析价值；
//  3. 存活超过 MaxAgeSeconds —— 防长期不关闭的连接（如被劫持的 keepalive）撑爆内存。
func (a *Aggregator) evictLocked(now time.Time) []string {
	idle := time.Duration(a.IdleSeconds) * time.Second
	if idle <= 0 {
		idle = defaultIdleSeconds * time.Second
	}
	maxAge := time.Duration(a.MaxAgeSeconds) * time.Second
	if maxAge <= 0 {
		maxAge = defaultMaxAgeSeconds * time.Second
	}
	grace := closedGraceSeconds * time.Second
	if grace > idle {
		grace = idle
	}

	var evicted []string
	for key, st := range a.sessions {
		quiet := now.Sub(st.seenAt)
		age := now.Sub(st.bornAt)
		switch {
		case st.session.Closed && quiet > grace:
		case quiet > idle:
		case age > maxAge:
		default:
			continue
		}
		delete(a.sessions, key)
		evicted = append(evicted, key)
	}
	a.evictedTotal += int64(len(evicted))
	return evicted
}

// Stats 返回会话表运行时指标。
func (a *Aggregator) Stats() AggregatorStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	max := a.MaxSessions
	return AggregatorStats{
		Active:      len(a.sessions),
		MaxSessions: max,
		Dropped:     a.dropped,
		Evicted:     a.evictedTotal,
	}
}

// Sessions 返回当前会话快照（不计算心跳）。
func (a *Aggregator) Sessions() []model.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]model.Session, 0, len(a.sessions))
	for _, st := range a.sessions {
		out = append(out, *st.session)
	}
	return out
}
