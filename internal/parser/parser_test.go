package parser

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestJA3KnownVector JA3 官方案例向量：
// ja3 字符串 "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
// 对应 MD5 = ada70206e40642a3e4461f35503241d5（实测校验值）
func TestJA3KnownVector(t *testing.T) {
	version := uint16(769)
	ciphers := []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4}
	exts := []uint16{0, 10, 11}
	curves := []uint16{23, 24, 25}
	pf := []byte{0}

	got := JA3String(version, ciphers, exts, curves, pf)
	want := "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	if got != want {
		t.Fatalf("JA3String = %q, want %q", got, want)
	}
	sum := md5.Sum([]byte(want))
	wantHash := hex.EncodeToString(sum[:])
	if h := JA3(version, ciphers, exts, curves, pf); h != wantHash {
		t.Fatalf("JA3 = %q, want %q", h, wantHash)
	}
	if wantHash != "ada70206e40642a3e4461f35503241d5" {
		t.Fatalf("已知向量 MD5 变化: %q", wantHash)
	}
}

// TestJA3GREASE GREASE 值应被剔除
func TestJA3GREASE(t *testing.T) {
	s1 := JA3String(771, []uint16{0x0a0a, 1301}, []uint16{0x1a1a, 0}, nil, nil)
	s2 := JA3String(771, []uint16{1301}, []uint16{0}, nil, nil)
	if s1 != s2 {
		t.Fatalf("GREASE 未被剔除: %q vs %q", s1, s2)
	}
}

// TestParseClientHelloAndJA3 手工构造 ClientHello，验证 SNI/JA3 提取
func TestParseClientHelloAndJA3(t *testing.T) {
	// 构造最小 ClientHello：TLS1.2, cipher 0x1301, ext: SNI=example.com
	var body []byte
	body = append(body, 0x03, 0x03)             // version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression
	// extensions
	var ext []byte
	// SNI ext
	name := "example.com"
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	u24 := func(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }
	var sni []byte
	sni = append(sni, u16(len(name)+3)...) // list len
	sni = append(sni, 0x00)                // host_name type
	sni = append(sni, u16(len(name))...)
	sni = append(sni, name...)
	ext = append(ext, 0x00, 0x00)
	ext = append(ext, u16(len(sni))...)
	ext = append(ext, sni...)
	body = append(body, u16(len(ext))...)
	body = append(body, ext...)

	hs := []byte{0x01}
	hs = append(hs, u24(len(body))...)
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	rec = append(rec, hs...)

	ch := ParseClientHello(rec)
	if ch == nil {
		t.Fatal("ParseClientHello 返回 nil")
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI = %q, want example.com", ch.SNI)
	}
	if ch.Version != 0x0303 {
		t.Fatalf("Version = %x", ch.Version)
	}
	if len(ch.Ciphers) != 1 || ch.Ciphers[0] != 0x1301 {
		t.Fatalf("Ciphers = %v", ch.Ciphers)
	}
	ja3 := JA3(ch.Version, ch.Ciphers, ch.Extensions, ch.Curves, ch.PointFormats)
	if len(ja3) != 32 {
		t.Fatalf("JA3 长度异常: %q", ja3)
	}
	ja4 := JA4("t", ch.Version, ch.SNI != "", ch.Ciphers, ch.Extensions, ch.SigAlgs, "")
	if ja4 == "" || ja4[:1] != "t" {
		t.Fatalf("JA4 异常: %q", ja4)
	}
}

// TestExtractHTTPHost HTTP Host 提取
func TestExtractHTTPHost(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: www.test.com:8080\r\n\r\n")
	if h := ExtractHTTPHost(payload); h != "www.test.com:8080" {
		t.Fatalf("Host = %q", h)
	}
	if h := ExtractHTTPHost([]byte("NOTHTTP data")); h != "" {
		t.Fatalf("非 HTTP 应返回空: %q", h)
	}
}

// TestAggregator 会话聚合：字节计数、方向、关闭、SNI/JA3、长连接、心跳
func TestAggregator(t *testing.T) {
	agg := NewAggregator(3600, 64)
	base := time.Now()

	mk := func(srcIP, dstIP string, sp, dp uint16, length int, payload []byte, flags uint8, ts time.Time) *PacketInfo {
		return &PacketInfo{
			Timestamp: ts, SrcMAC: "aa:bb:cc:dd:ee:ff", SrcIP: srcIP, DstIP: dstIP,
			SrcPort: sp, DstPort: dp, Proto: "tcp", TTL: 64, Length: length,
			Payload: payload, TCPFlags: flags,
		}
	}

	// 客户端 10.0.0.1:5000 → 1.1.1.1:443，10 个小包，固定 100ms 间隔（心跳）
	for i := 0; i < 10; i++ {
		agg.Ingest(mk("10.0.0.1", "1.1.1.1", 5000, 443, 40, nil, 0x10, base.Add(time.Duration(i*100)*time.Millisecond)))
		agg.Ingest(mk("1.1.1.1", "10.0.0.1", 443, 5000, 40, nil, 0x10, base.Add(time.Duration(i*100+50)*time.Millisecond)))
	}
	// HTTP Host
	agg.Ingest(mk("10.0.0.1", "1.1.1.1", 5000, 443, 100,
		[]byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"), 0x10, base.Add(2*time.Second)))
	// 反向包应聚合进同一会话（五元组归一化）
	agg.Ingest(mk("1.1.1.1", "10.0.0.1", 443, 5000, 1500, nil, 0x10, base.Add(3*time.Second)))
	// FIN 关闭
	agg.Ingest(mk("10.0.0.1", "1.1.1.1", 5000, 443, 40, nil, 0x01, base.Add(3601*time.Second)))

	sessions := agg.Finalize()
	if len(sessions) != 1 {
		t.Fatalf("会话数 = %d, want 1", len(sessions))
	}
	ses := sessions[0]
	if ses.Packets != 23 {
		t.Fatalf("Packets = %d, want 23", ses.Packets)
	}
	if ses.BytesUp == 0 || ses.BytesDown == 0 {
		t.Fatalf("上下行字节未分别计数: up=%d down=%d", ses.BytesUp, ses.BytesDown)
	}
	if !ses.Closed {
		t.Fatal("FIN 后应标记 Closed")
	}
	if ses.HTTPHost != "a.com" {
		t.Fatalf("HTTPHost = %q", ses.HTTPHost)
	}
	if ses.HeartbeatIntervalMs == 0 {
		t.Fatal("应识别心跳间隔")
	}
	if !ses.IsLongConn {
		t.Fatal("超过 1h 应判定为长连接")
	}
	if ses.StartTTL != 64 {
		t.Fatalf("StartTTL = %d", ses.StartTTL)
	}
	_ = model.FiveTuple{}.Key()
}
