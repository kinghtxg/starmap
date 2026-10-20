package parser

import (
	"strings"
	"testing"
	"time"
)

func req(headers ...string) []byte {
	s := "GET /index.html HTTP/1.1\r\nHost: portal.gov.local\r\n"
	for _, h := range headers {
		s += h + "\r\n"
	}
	return []byte(s + "\r\n")
}

func TestExtractForwardedSingle(t *testing.T) {
	fi := ExtractForwarded(req("X-Forwarded-For: 203.0.113.7"))
	if fi.RealClient != "203.0.113.7" {
		t.Fatalf("真实客户端=%q", fi.RealClient)
	}
	if fi.Host != "portal.gov.local" {
		t.Fatalf("Host 未顺带返回: %q", fi.Host)
	}
	if len(fi.XFF) != 1 || fi.XFF[0] != "203.0.113.7" {
		t.Fatalf("XFF=%v", fi.XFF)
	}
}

func TestExtractForwardedChain(t *testing.T) {
	// 客户端 → 代理1 → 代理2 → 服务，链序为最原始在前
	fi := ExtractForwarded(req("X-Forwarded-For: 10.0.0.5, 10.0.0.1, 10.0.0.2"))
	if len(fi.XFF) != 3 {
		t.Fatalf("XFF=%v", fi.XFF)
	}
	if fi.RealClient != "10.0.0.5" {
		t.Fatalf("首跳应是最原始客户端，实际=%q", fi.RealClient)
	}
}

func TestExtractForwardedMultiHeader(t *testing.T) {
	fi := ExtractForwarded(req("X-Forwarded-For: 10.0.0.5", "X-Forwarded-For: 10.0.0.1"))
	if len(fi.XFF) != 2 || fi.XFF[1] != "10.0.0.1" {
		t.Fatalf("多行 XFF 未按顺序合并: %v", fi.XFF)
	}
}

func TestExtractForwardedPortAndIPv6(t *testing.T) {
	fi := ExtractForwarded(req("X-Forwarded-For: 10.0.0.5:51234, [2001:db8::1]:443, 2001:db8::2"))
	want := []string{"10.0.0.5", "2001:db8::1", "2001:db8::2"}
	if len(fi.XFF) != len(want) {
		t.Fatalf("XFF=%v", fi.XFF)
	}
	for i := range want {
		if fi.XFF[i] != want[i] {
			t.Fatalf("第 %d 跳=%q 期望 %q", i, fi.XFF[i], want[i])
		}
	}
}

func TestExtractForwardedRealIPOnly(t *testing.T) {
	fi := ExtractForwarded(req("X-Real-IP: 10.0.0.9"))
	if fi.RealClient != "10.0.0.9" || fi.XRealIP != "10.0.0.9" {
		t.Fatalf("X-Real-IP 兜底失败: %+v", fi)
	}
	if len(fi.XFF) != 0 {
		t.Fatalf("不应凭空造 XFF: %v", fi.XFF)
	}
}

func TestExtractForwardedRFC7239(t *testing.T) {
	fi := ExtractForwarded(req("Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43, for=198.51.100.17"))
	if len(fi.XFF) != 2 || fi.XFF[0] != "192.0.2.60" {
		t.Fatalf("RFC 7239 回落解析失败: %v", fi.XFF)
	}
	if fi.RealClient != "192.0.2.60" {
		t.Fatalf("RealClient=%q", fi.RealClient)
	}
}

func TestExtractForwardedSkipsInvalid(t *testing.T) {
	fi := ExtractForwarded(req("X-Forwarded-For: unknown, not-an-ip, 10.0.0.5, _hidden"))
	if len(fi.XFF) != 1 || fi.XFF[0] != "10.0.0.5" {
		t.Fatalf("非法值未跳过: %v", fi.XFF)
	}
}

func TestExtractForwardedNonHTTP(t *testing.T) {
	if fi := ExtractForwarded([]byte("NOTHTTP just some binary payload")); fi.RealClient != "" || len(fi.XFF) > 0 {
		t.Fatalf("非 HTTP 载荷不应解析出转发链: %+v", fi)
	}
	// TLS ClientHello 首个字节 0x16
	if fi := ExtractForwarded([]byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00}); fi.RealClient != "" {
		t.Fatal("TLS 载荷不应误判为 HTTP")
	}
}

func TestExtractForwardedHopsCapped(t *testing.T) {
	// 构造超长链：客户端可写 → 必须先截断再解析，防止拖慢/撑爆。
	// 40 跳在 32KB 头上限之内，但超过 maxForwardedHops。
	var b strings.Builder
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("10.0.0.1")
	}
	fi := ExtractForwarded(req("X-Forwarded-For: " + b.String()))
	if len(fi.XFF) != maxForwardedHops {
		t.Fatalf("跳数=%d 期望上限 %d", len(fi.XFF), maxForwardedHops)
	}
}

func TestExtractForwardedOversizePayload(t *testing.T) {
	// 超过头上限：直接放弃解析，不 panic、不返回半截错误结果
	big := req("X-Forwarded-For: 10.0.0.5", "X-Pad: "+strings.Repeat("a", 40000))
	if fi := ExtractForwarded(big); fi.RealClient != "" {
		t.Fatalf("超限载荷不应产出结果: %q", fi.RealClient)
	}
}

// TestAggregatorCapturesXFF 会话聚合要把转发链挂到 Session 上（本地抓包路径）。
func TestAggregatorCapturesXFF(t *testing.T) {
	agg := NewAggregator(3600, 64)
	ts := time.Now()
	agg.Ingest(&PacketInfo{
		Timestamp: ts, SrcMAC: "aa:bb:cc:dd:ee:ff",
		SrcIP: "10.0.0.100", DstIP: "10.0.0.200",
		SrcPort: 40000, DstPort: 80, Proto: "tcp", TTL: 64, Length: 900,
		Payload: req("X-Forwarded-For: 10.0.0.5, 10.0.0.1"),
	})
	sessions := agg.Finalize()
	if len(sessions) != 1 {
		t.Fatalf("会话数=%d", len(sessions))
	}
	s := sessions[0]
	if len(s.XFF) != 2 || s.RealClientIP != "10.0.0.5" || s.ProxyHops != 2 {
		t.Fatalf("会话未携带转发链: xff=%v real=%q hops=%d", s.XFF, s.RealClientIP, s.ProxyHops)
	}
	if s.HTTPHost != "portal.gov.local" {
		t.Fatalf("同一次解析应顺带填好 Host: %q", s.HTTPHost)
	}
}
