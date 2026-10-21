package parser

import (
	"testing"
)

// 这三个解析函数都跑在「报文路径」上：线上每来一个包就会被调用一次。
// 它们一旦 panic，整个被动分析流水线就断了 —— 所以用 fuzz 反复喂畸形输入，
// 守住「任何字节序列都不 panic」这条底线。
//
// 常规验证：go test ./internal/parser/
// 深度模糊：go test ./internal/parser/ -fuzz=FuzzExtractForwarded -fuzztime=60s

func FuzzExtractForwarded(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: a.com\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4, 5.6.7.8\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Real-IP: 192.168.1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nForwarded: for=1.1.1.1;proto=https, for=\"[::1]:8080\"\r\n\r\n",
		"GET / HTTP/1.1\r\nVia: 1.1 proxy\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Forwarded-For: unknown, _hidden, 10.0.0.1\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1:8080\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Forwarded-For: \r\n\r\n",
		"",
		"\x16\x03\x01\x00\x05hello",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		info := ExtractForwarded(data)
		// 结果自洽性：RealClient 若存在，必须能在 XFF 或 X-Real-IP 里找到出处
		if info.RealClient != "" && len(info.XFF) == 0 && info.XRealIP == "" {
			t.Fatalf("RealClient=%q 但既无 XFF 也无 X-Real-IP", info.RealClient)
		}
		// 跳数不得超过解析上限
		if len(info.XFF) > maxForwardedHops {
			t.Fatalf("XFF 跳数 %d 超过上限 %d", len(info.XFF), maxForwardedHops)
		}
	})
}

func FuzzParseClientHello(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03})
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		// 只要求不 panic：返回 nil 属正常（非 ClientHello / 畸形）
		_ = ParseClientHello(data)
	})
}

func FuzzExtractHTTPHost(f *testing.F) {
	f.Add([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST / HTTP/1.0\r\nhost: a.b\r\n\r\n"))
	f.Add([]byte("garbage"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ExtractHTTPHost(data)
	})
}

func FuzzJA4(f *testing.F) {
	f.Add(uint16(0x0303), "h2,http/1.1", []byte{0x01, 0x13, 0x02, 0x13})
	f.Add(uint16(0), "", []byte{})
	f.Add(uint16(0xffff), "\x00\xff", []byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, ver uint16, alpn string, raw []byte) {
		// raw 按 2 字节切分为 uint16 序列，保证切片内容也来自模糊输入
		toU16 := func(b []byte) []uint16 {
			out := make([]uint16, 0, len(b)/2)
			for i := 0; i+1 < len(b); i += 2 {
				out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
			}
			return out
		}
		ciphers := toU16(raw)
		exts := toU16(raw)
		_ = JA3(ver, ciphers, exts, nil, nil)
		_ = JA4("t", ver, true, ciphers, exts, nil, alpn)
	})
}
