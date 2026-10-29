package parser

import (
	"testing"
	"time"
)

// 明文 HTTP 的身份线索提取（V1.5）。

func TestParseHTTPMetaRequest(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: nas.local:5000\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n\r\n")
	m := ParseHTTPMeta(payload)
	if m == nil {
		t.Fatal("应解析出 HTTP 元数据")
	}
	if !m.IsRequest {
		t.Fatal("应判定为请求")
	}
	if m.Host != "nas.local:5000" {
		t.Fatalf("Host = %q", m.Host)
	}
	if m.UserAgent == "" {
		t.Fatal("应提取到 User-Agent")
	}
	// 请求里不该冒出发应答侧的字段
	if m.Server != "" {
		t.Fatalf("请求不应有 Server 字段，实际 %q", m.Server)
	}
}

func TestParseHTTPMetaResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n" +
		"X-Powered-By: PHP/7.4.3\r\nContent-Length: 0\r\n\r\n")
	m := ParseHTTPMeta(payload)
	if m == nil {
		t.Fatal("应解析出 HTTP 元数据")
	}
	if m.IsRequest {
		t.Fatal("应判定为应答")
	}
	if m.Server != "nginx/1.18.0 (Ubuntu)" {
		t.Fatalf("Server = %q", m.Server)
	}
	if m.PoweredBy != "PHP/7.4.3" {
		t.Fatalf("PoweredBy = %q", m.PoweredBy)
	}
	if m.UserAgent != "" {
		t.Fatalf("应答不应有 UA，实际 %q", m.UserAgent)
	}
}

func TestParseHTTPMetaRejectsNonHTTP(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("short"),
		[]byte("NOTHTTP data but long enough to pass length check"),
		[]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x00, 0x00},
		// 应答但没有 Server / X-Powered-By：没有身份信息，不值得占内存
		[]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
	}
	for _, c := range cases {
		if m := ParseHTTPMeta(c); m != nil {
			t.Fatalf("不应解析出元数据，输入 %q → %+v", c, m)
		}
	}
}

// 端到端：请求里的 UA 落到会话 UserAgent，应答里的 Server 落到 HTTPServer。
func TestAggregatorCapturesHTTPMeta(t *testing.T) {
	agg := NewAggregator(3600, 64)
	base := time.Now()
	mk := func(srcIP, dstIP string, sp, dp uint16, payload []byte, ts time.Time) *PacketInfo {
		return &PacketInfo{
			Timestamp: ts, SrcMAC: "aa:bb:cc:dd:ee:ff", SrcIP: srcIP, DstIP: dstIP,
			SrcPort: sp, DstPort: dp, Proto: "tcp", TTL: 128, Length: 200, Payload: payload,
		}
	}
	agg.Ingest(mk("192.168.31.20", "192.168.31.100", 50123, 80,
		[]byte("GET / HTTP/1.1\r\nHost: nas.local\r\nUser-Agent: curl/8.4.0\r\n\r\n"), base))
	agg.Ingest(mk("192.168.31.100", "192.168.31.20", 80, 50123,
		[]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"),
		base.Add(time.Second)))

	sessions := agg.Finalize()
	if len(sessions) != 1 {
		t.Fatalf("会话数 = %d, want 1", len(sessions))
	}
	if got := sessions[0].UserAgent; got != "curl/8.4.0" {
		t.Fatalf("UserAgent = %q", got)
	}
	if got := sessions[0].HTTPServer; got != "nginx/1.18.0" {
		t.Fatalf("HTTPServer = %q", got)
	}
	// 已有的 Host 提取不能被新逻辑破坏
	if got := sessions[0].HTTPHost; got != "nas.local" {
		t.Fatalf("HTTPHost = %q", got)
	}
}
