// Package pcapgen 合成 PCAP 生成库（SPEC §8 / ACCEPTANCE 11.1）。
// 供 testdata/gen_pcap.go（生成落盘文件）与集成测试（内存字节）共用，
// 保证 5 类场景特征一致：正常办公 / FRP / Clash / 反代多 Host / 跨网域双域。
package pcapgen

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Base 全部场景的基准时间（>1h 长连接通过构造时间戳实现，SPEC §10.2）
var Base = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)

// ---------- TLS ClientHello 构造 ----------

type ext struct {
	typ  uint16
	data []byte
}

func u16b(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
func u24b(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

func sniExt(name string) ext {
	var d []byte
	d = append(d, u16b(len(name)+3)...)
	d = append(d, 0x00)
	d = append(d, u16b(len(name))...)
	d = append(d, name...)
	return ext{0x0000, d}
}

func alpnExt(proto string) ext {
	d := []byte{0x00, byte(len(proto) + 1), byte(len(proto))}
	d = append(d, proto...)
	return ext{0x0010, d}
}

func u16ListExt(typ uint16, vals ...uint16) ext {
	d := u16b(len(vals) * 2)
	for _, v := range vals {
		d = append(d, u16b(int(v))...)
	}
	return ext{typ, d}
}

// ClientHello 构造 TLS ClientHello record。
// version 为 ClientHello 版本字段；ciphers/exts 长度决定 JA4 a 段计数。
func ClientHello(sni string, version uint16, ciphers []uint16, exts []ext, alpn string) []byte {
	var body []byte
	body = append(body, byte(version>>8), byte(version))
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len
	body = append(body, u16b(len(ciphers)*2)...)
	for _, c := range ciphers {
		body = append(body, u16b(int(c))...)
	}
	body = append(body, 0x01, 0x00) // null compression
	var eb []byte
	for _, e := range exts {
		eb = append(eb, u16b(int(e.typ))...)
		eb = append(eb, u16b(len(e.data))...)
		eb = append(eb, e.data...)
	}
	body = append(body, u16b(len(eb))...)
	body = append(body, eb...)
	hs := append([]byte{0x01}, u24b(len(body))...)
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16b(len(hs))...)
	return append(rec, hs...)
}

// Go 风格 cipher 列表（15 个，Go crypto/tls 默认常见组合）
var goCiphers = []uint16{
	0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
	0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d,
}

// GoTLSCipherCount Go 客户端 hello 的扩展数（16）用于 JA4 t13d1516h2。
func goExts(sni string) []ext {
	return []ext{
		sniExt(sni),                                // 0
		{0x0005, []byte{1, 0, 0, 0, 0}},            // status_request
		u16ListExt(0x000a, 29, 23, 24),             // supported_groups
		{0x000b, []byte{1, 0}},                     // ec_point_formats
		u16ListExt(0x000d, 0x0403, 0x0804, 0x0401), // signature_algorithms
		alpnExt("h2"),                              // 16
		{0x0012, nil},                              // SCT
		{0x0017, nil},                              // extended_master_secret
		{0x001b, []byte{2, 2}},                     // compress_certificate
		{0x0021, []byte{4, 0, 0, 0, 0}},            // pre_shared_key (fake)
		{0x0015, nil},                              // padding
		{0x002b, []byte{2, 0x03, 0x04}},            // supported_versions
		{0x002d, []byte{1, 1}},                     // psk_key_exchange_modes
		{0x0033, []byte{2, 0, 0}},                  // key_share (fake)
		{0x0023, nil},                              // session_ticket
		{0xff01, []byte{0}},                        // renegotiation_info
	}
}

// GoClientHello 生成匹配 Go-TLS JA4 前缀（t13d1516h2）的 ClientHello：
// 版本 0x0304、带 SNI、15 ciphers、16 exts、ALPN h2。
func GoClientHello(sni string) []byte {
	return ClientHello(sni, 0x0304, goCiphers, goExts(sni), "h2")
}

// GenericClientHello 生成普通客户端 ClientHello（不匹配 Go-TLS 指纹）。
func GenericClientHello(sni string) []byte {
	return ClientHello(sni, 0x0303, []uint16{0x1301, 0xc02f, 0xcca8}, []ext{
		sniExt(sni),
		u16ListExt(0x000a, 23, 24),
		{0x000b, []byte{1, 0}},
	}, "")
}

// HTTPGet 构造最小 HTTP 请求。
func HTTPGet(host string) []byte {
	return []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: starmap-test\r\n\r\n", host))
}

// ---------- 报文与文件构造 ----------

type packet struct {
	ts      time.Time
	srcMAC  string
	dstMAC  string
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	flags   uint8 // bit0 FIN bit1 SYN bit2 RST bit4 ACK
	payload []byte
}

// Writer 累积报文并序列化为 PCAP 字节。
type Writer struct{ pkts []packet }

func (w *Writer) add(p packet) { w.pkts = append(w.pkts, p) }

// TCP 追加一个 TCP 报文。
func (w *Writer) TCP(ts time.Time, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, flags uint8, payload []byte) {
	w.add(packet{ts, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, flags, payload})
}

// Bytes 序列化为经典 PCAP（LinkTypeEthernet）。
func (w *Writer) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	pw := pcapgo.NewWriter(&buf)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	for _, p := range w.pkts {
		sm, _ := net.ParseMAC(p.srcMAC)
		dm, _ := net.ParseMAC(p.dstMAC)
		eth := &layers.Ethernet{SrcMAC: sm, DstMAC: dm, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64,
			SrcIP: net.ParseIP(p.srcIP).To4(), DstIP: net.ParseIP(p.dstIP).To4(),
			Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.srcPort), DstPort: layers.TCPPort(p.dstPort), Seq: 1}
		tcp.FIN = p.flags&0x01 != 0
		tcp.SYN = p.flags&0x02 != 0
		tcp.RST = p.flags&0x04 != 0
		tcp.ACK = p.flags&0x10 != 0
		tcp.PSH = len(p.payload) > 0
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil, err
		}
		sb := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(sb, opts, eth, ip, tcp, gopacket.Payload(p.payload)); err != nil {
			return nil, err
		}
		data := sb.Bytes()
		if err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp: p.ts, CaptureLength: len(data), Length: len(data),
		}, data); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

const gwMAC = "02:00:00:00:00:fe"

// ---------- 5 大场景（ACCEPTANCE 11.1） ----------

// NormalOffice ①正常办公：内网互访 + 常见 HTTPS（SNI 正常、短会话、无心跳、无长连接）。
func NormalOffice() ([]byte, error) {
	w := &Writer{}
	macA := "02:00:00:0a:14:0a"
	// 内网互访 10.20.0.10 ↔ 10.20.0.11（文件共享，持续 30s，双向各 6 包 500B）
	for i := 0; i < 6; i++ {
		t := Base.Add(time.Duration(i*6) * time.Second)
		w.TCP(t, macA, "02:00:00:0a:14:0b", "10.20.0.10", "10.20.0.11", 41000, 445, 0x10, make([]byte, 500))
		w.TCP(t.Add(time.Second), "02:00:00:0a:14:0b", macA, "10.20.0.11", "10.20.0.10", 445, 41000, 0x10, make([]byte, 500))
	}
	// 常见 HTTPS：10.20.0.10 → 93.184.216.34:443（SNI www.example.com，5s 结束）
	t0 := Base.Add(2 * time.Minute)
	w.TCP(t0, macA, gwMAC, "10.20.0.10", "93.184.216.34", 42000, 443, 0x10, GenericClientHello("www.example.com"))
	for i := 1; i <= 4; i++ {
		w.TCP(t0.Add(time.Duration(i)*time.Second), "02:00:00:00:00:01", macA, "93.184.216.34", "10.20.0.10", 443, 42000, 0x10, make([]byte, 400))
		w.TCP(t0.Add(time.Duration(i)*time.Second).Add(200*time.Millisecond), macA, gwMAC, "10.20.0.10", "93.184.216.34", 42000, 443, 0x10, make([]byte, 200))
	}
	return w.Bytes()
}

// FRP ②FRP 特征：Go-TLS ClientHello（JA4 t13d1516h2）+ >1h 时间戳长连接 + 30s 周期小包心跳。
// 三项全中 → 期望 type=frp, level=high。
func FRP(srcIP, srcMAC string, sport uint16) ([]byte, error) {
	w := &Writer{}
	dstIP := "203.0.113.10"
	// t=0：Go-TLS ClientHello（JA3/JA4 指纹命中）
	w.TCP(Base, srcMAC, gwMAC, srcIP, dstIP, sport, 7000, 0x10, GoClientHello("tunnel-node.example.net"))
	// 30s 周期心跳：空载荷小包（IP 总长 40B < 64B 阈值）
	for i := 1; i <= 5; i++ {
		w.TCP(Base.Add(time.Duration(i*30)*time.Second), srcMAC, gwMAC, srcIP, dstIP, sport, 7000, 0x10, nil)
	}
	// t=+3700s：收尾 FIN（跨度 > 3600s → 长连接保活）
	w.TCP(Base.Add(3700*time.Second), srcMAC, gwMAC, srcIP, dstIP, sport, 7000, 0x11, nil)
	return w.Bytes()
}

// Clash ③Clash 特征：随机高熵 SNI + 高频短间隔公网外联（12 个短会话）+ ≥5 陌生目的 /24。
// 注意 SNI 去重数控制在 10（避免误触反代阈值 10）。
func Clash(srcIP, srcMAC string) ([]byte, error) {
	w := &Writer{}
	snis := []string{
		"q7zk29xwm8vb.com", "m3v8q1z6xk2w.net", "z9x2w7q4v8m3k1.org",
		"k1w8v3z6q9x2m4.io", "x5m9q2w8z3v7k6.cn", "v2k7x4m9q3w8z1.net",
		"w4z1q8x6m2v9k3.com", "q8v3m1x9w4z7k2.org", "z6q9w2x8m3v1k7.net",
		"m9x3w7q2v8k1z4.com",
	}
	dstSubnets := []string{
		"45.67.89", "104.21.33", "172.67.150", "185.199.108", "142.250.72",
		"151.101.1", "13.107.42", "52.84.150", "99.86.229", "157.240.1",
		"31.13.72", "108.177.97",
	}
	for i := 0; i < 12; i++ {
		sni := snis[i%len(snis)]
		dst := dstSubnets[i] + ".1"
		sport := uint16(52000 + i)
		t0 := Base.Add(time.Duration(i*45) * time.Second) // 高频短间隔
		w.TCP(t0, srcMAC, gwMAC, srcIP, dst, sport, 443, 0x10, GenericClientHello(sni))
		w.TCP(t0.Add(300*time.Millisecond), "02:00:00:00:00:01", srcMAC, dst, srcIP, 443, sport, 0x10, make([]byte, 300))
	}
	return w.Bytes()
}

// ReverseProxy ④反代特征：多台客户端访问**同一台内网服务器**，Host 各不相同（阈值 10）。
//
// 方向必须是"客户端 → 内网服务器"。这里曾经反过来构造：单台内网主机向公网
// 203.0.113.80 发起 12 个不同 Host 的请求——那描述的是一台电脑在浏览网页，
// 而规则当时按"源 IP"统计 SNI，于是把它当成了反代。夹具和规则一起错，
// 测试就一直"通过"，直到接进真实网络才在值班主机上炸出来。
func ReverseProxy(srcIP, srcMAC string) ([]byte, error) {
	w := &Writer{}
	// srcIP 扮演同一台内网反代服务器，被下列客户端访问
	const serverMAC = "02:00:00:00:00:01"
	for i := 1; i <= 12; i++ {
		clientIP := fmt.Sprintf("10.40.1.%d", i)
		clientMAC := fmt.Sprintf("02:00:00:0a:28:%02x", i)
		sport := uint16(53000 + i)
		host := fmt.Sprintf("app%02d.internal-sites.example.org", i)
		t0 := Base.Add(time.Duration(i*10) * time.Second)
		w.TCP(t0, clientMAC, gwMAC, clientIP, srcIP, sport, 80, 0x10, HTTPGet(host))
		w.TCP(t0.Add(500*time.Millisecond), serverMAC, clientMAC, srcIP, clientIP, 80, sport, 0x10,
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\n"+string(make([]byte, 400))))
	}
	return w.Bytes()
}

// MultiNet ⑤跨网域融合：同 MAC 的两个 IP 分别命中 gov(10.0.0.0/8) 与 office(172.16.0.0/12) 域。
func MultiNet() ([]byte, error) {
	w := &Writer{}
	sharedMAC := "02:00:00:00:00:99"
	payload := make([]byte, 300)
	// gov 域：10.8.0.10 ↔ 10.8.0.20
	for i := 0; i < 4; i++ {
		t := Base.Add(time.Duration(i*5) * time.Second)
		w.TCP(t, sharedMAC, "02:00:00:0a:08:14", "10.8.0.10", "10.8.0.20", 54000, 8443, 0x10, payload)
		w.TCP(t.Add(time.Second), "02:00:00:0a:08:14", sharedMAC, "10.8.0.20", "10.8.0.10", 8443, 54000, 0x10, payload)
	}
	// office 域：172.16.9.10 ↔ 172.16.9.20（同 MAC）
	for i := 0; i < 4; i++ {
		t := Base.Add(time.Minute + time.Duration(i*5)*time.Second)
		w.TCP(t, sharedMAC, "02:00:00:ac:10:14", "172.16.9.10", "172.16.9.20", 54001, 9443, 0x10, payload)
		w.TCP(t.Add(time.Second), "02:00:00:ac:10:14", sharedMAC, "172.16.9.20", "172.16.9.10", 9443, 54001, 0x10, payload)
	}
	return w.Bytes()
}

// Scenarios 场景名 → 生成函数（gen_pcap 与集成测试共用的清单）。
func Scenarios() map[string]func() ([]byte, error) {
	return map[string]func() ([]byte, error){
		"normal_office.pcap": NormalOffice,
		"frp_tunnel.pcap":    func() ([]byte, error) { return FRP("10.20.0.50", "02:00:00:0a:14:32", 51000) },
		"clash_proxy.pcap":   func() ([]byte, error) { return Clash("10.30.0.60", "02:00:00:0a:1e:3c") },
		"reverse_proxy.pcap": func() ([]byte, error) { return ReverseProxy("10.40.0.70", "02:00:00:0a:28:46") },
		"multi_net.pcap":     MultiNet,
	}
}
