package parser

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
)

// maxForwardedHops 转发链最大解析跳数。
// XFF 是客户端可写的文本，构造超长链（几万跳）会拖慢解析并撑爆内存，必须设上限。
const maxForwardedHops = 8

// maxForwardedHeaderBytes 单次 HTTP 头解析上限。
// 常见的 nginx large_client_header_buffers 是 8KB，留 4 倍余量容忍异常大的正常请求；
// 超过即放弃解析（截断后请求行不完整，解析必然失败，不做无用功）。
const maxForwardedHeaderBytes = 32 << 10

// ForwardedInfo 七层转发头解析结果（V1.8）。
//
// 为什么要它：请求经过 nginx / HAProxy / SLB / API 网关后，被动流量侧只能看到
// 代理 IP，真实客户端被一个 IP 完全遮蔽——资产测绘会把"一台代理"当成"一台设备"，
// 代理后面几百台客户端全部不可见。XFF 是这类转发链里唯一能还原真实源头的明文证据。
type ForwardedInfo struct {
	Host       string   // Host 头（与 ExtractHTTPHost 一致，顺带返回避免二次解析）
	XFF        []string // X-Forwarded-For 链，按出现顺序：XFF[0] 为最原始客户端
	XRealIP    string   // X-Real-IP（nginx 常见）
	Forwarded  string   // RFC 7239 Forwarded 原始值
	Via        string   // Via 原始值（代理链痕迹）
	RealClient string   // 还原出的真实客户端：优先 XFF[0]，否则 X-Real-IP
}

// httpReqPrefixes 常见 HTTP 请求方法前缀，用于快速排除非 HTTP 载荷。
var httpReqPrefixes = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
}

func looksLikeHTTPRequest(payload []byte) bool {
	if len(payload) < 16 {
		return false
	}
	for _, p := range httpReqPrefixes {
		if bytes.HasPrefix(payload, []byte(p)) {
			return true
		}
	}
	return false
}

// ExtractForwarded 从 HTTP 请求载荷中提取转发链。
//
// 只解析请求方向且以常见方法开头的载荷（响应里不会有 XFF，客户端也没法伪造出请求行）。
// 解析失败一律返回零值，绝不 panic——这是跑在流量路径上的代码。
func ExtractForwarded(payload []byte) ForwardedInfo {
	var fi ForwardedInfo
	if len(payload) > maxForwardedHeaderBytes {
		payload = payload[:maxForwardedHeaderBytes]
	}
	if !looksLikeHTTPRequest(payload) {
		return fi
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return fi
	}
	fi.Host = req.Host

	// X-Forwarded-For 允许多行（每行再逗号分隔），全部按出现顺序拼接
	for _, v := range req.Header.Values("X-Forwarded-For") {
		fi.XFF = append(fi.XFF, parseForwardedChain(v)...)
		if len(fi.XFF) >= maxForwardedHops {
			break
		}
	}
	if len(fi.XFF) > maxForwardedHops {
		fi.XFF = fi.XFF[:maxForwardedHops]
	}

	fi.XRealIP = normalizeForwardedIP(req.Header.Get("X-Real-IP"))
	if len(req.Header.Values("Forwarded")) > 0 {
		fi.Forwarded = strings.Join(req.Header.Values("Forwarded"), ", ")
		// 只有 XFF 缺失时才回落到 RFC 7239 的 for=
		if len(fi.XFF) == 0 {
			fi.XFF = parseRFC7239(fi.Forwarded)
		}
	}
	fi.Via = strings.Join(req.Header.Values("Via"), ", ")

	if len(fi.XFF) > 0 {
		fi.RealClient = fi.XFF[0]
	} else {
		fi.RealClient = fi.XRealIP
	}
	return fi
}

// parseForwardedChain 解析 "client, proxy1, proxy2" 形式的链。
func parseForwardedChain(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if ip := normalizeForwardedIP(p); ip != "" {
			out = append(out, ip)
		}
		if len(out) >= maxForwardedHops {
			break
		}
	}
	return out
}

// parseRFC7239 解析 "for=192.0.2.60;proto=http, for=198.51.100.17" 形式。
func parseRFC7239(v string) []string {
	var out []string
	for _, elem := range strings.Split(v, ",") {
		for _, kv := range strings.Split(elem, ";") {
			kv = strings.TrimSpace(kv)
			if len(kv) > 4 && strings.EqualFold(kv[:4], "for=") {
				if ip := normalizeForwardedIP(kv[4:]); ip != "" {
					out = append(out, ip)
				}
			}
		}
		if len(out) >= maxForwardedHops {
			break
		}
	}
	return out
}

// normalizeForwardedIP 把转发头里的各种写法归一为纯 IP：
// 去引号、去 for= 前缀、去端口（1.2.3.4:5678 / [2001:db8::1]:443）、
// 跳过 unknown / _hidden / 非法值。
func normalizeForwardedIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	if len(s) > 4 && strings.EqualFold(s[:4], "for=") {
		s = strings.TrimSpace(s[4:])
		s = strings.Trim(s, `"`)
	}
	if strings.EqualFold(s, "unknown") || strings.EqualFold(s, "_hidden") {
		return ""
	}
	// [IPv6]:port 或 [IPv6]
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 1 {
			s = s[1:i]
		}
	} else if strings.Count(s, ":") == 1 {
		// 仅一个冒号 → 一定是 IPv4:port
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
	}
	if net.ParseIP(s) == nil {
		return ""
	}
	return s
}
