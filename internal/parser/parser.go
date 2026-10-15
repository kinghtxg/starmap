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

// sessionState 内存会话状态
type sessionState struct {
	session    *model.Session
	isClient   func(srcIP string, srcPort uint16) bool // 判断方向
	packetLens []int                                   // 小包长度序列（心跳判定）
	packetGaps []int64                                 // 相邻小包间隔 ms
	lastTs     time.Time
	helloDone  bool
	hostDone   bool
}

// Aggregator 内存会话表：按五元组聚合 PacketInfo 为 model.Session。
type Aggregator struct {
	mu       sync.Mutex
	sessions map[string]*sessionState
	// 判定参数（来自 SystemConfig）
	LongConnSeconds   int64
	HeartbeatMaxBytes int
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
	}
}

// Ingest 喂入一个报文，更新会话状态。
func (a *Aggregator) Ingest(p *PacketInfo) {
	if p == nil || p.SrcIP == "" {
		return
	}
	ft := model.FiveTuple{SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort, Proto: p.Proto}
	key := ft.Key()

	a.mu.Lock()
	defer a.mu.Unlock()

	st, ok := a.sessions[key]
	if !ok {
		ses := &model.Session{
			FiveTuple: ft,
			MAC:       p.SrcMAC,
			StartTTL:  p.TTL,
			FirstSeen: p.Timestamp,
			LastSeen:  p.Timestamp,
			Location:  p.Location,
		}
		st = &sessionState{session: ses}
		// 以"发起方端口 > 对端端口"作为客户端方向的粗略启发（临时端口）
		base := st.session
		st.isClient = func(srcIP string, srcPort uint16) bool {
			return srcIP == base.FiveTuple.SrcIP && srcPort == base.FiveTuple.SrcPort
		}
		a.sessions[key] = st
	} else if ses := st.session; ses.Location == "" && p.Location != "" {
		ses.Location = p.Location
	}

	ses := st.session
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
	if ses.HeartbeatIntervalMs == 0 && p.Length > 0 && p.Length <= a.HeartbeatMaxBytes {
		if !st.lastTs.IsZero() {
			st.packetGaps = append(st.packetGaps, p.Timestamp.Sub(st.lastTs).Milliseconds())
		}
		st.packetLens = append(st.packetLens, p.Length)
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

	// 长连接判定
	if ses.LastSeen.Sub(ses.FirstSeen).Seconds() >= float64(a.LongConnSeconds) {
		ses.IsLongConn = true
	}
}

// Finalize 完成聚合：计算心跳间隔，返回全部会话快照。
func (a *Aggregator) Finalize() []model.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]model.Session, 0, len(a.sessions))
	for _, st := range a.sessions {
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
		out = append(out, *ses)
	}
	return out
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
