// JA4 指纹计算（简化实现，遵循 JA4 TLS 客户端指纹规范核心结构）：
// a 段：协议(t=tcp)+TLS版本+SNI(d/i)+密码套件数+扩展数+ALPN，如 t13d1516h2
// b 段：排序后密码套件十六进制列表的 SHA256 前 12 位
// c 段：排序后扩展十六进制列表 + 签名算法列表的 SHA256 前 12 位
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// tlsVersionName 将 TLS 版本号映射为 JA4 两字符版本标记。
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// hashHexList 对十六进制（4 位小写）列表排序拼接后取 SHA256 前 12 位。
func hashHexList(items []string) string {
	if len(items) == 0 {
		return "000000000000"
	}
	sort.Strings(items)
	sum := sha256.Sum256([]byte(strings.Join(items, ",")))
	return hex.EncodeToString(sum[:])[:12]
}

func toHex4(vals []uint16) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return out
}

// JA4 计算 ClientHello 的 JA4 指纹。
// transport: "t"(TCP) 或 "q"(QUIC)；hasSNI: 是否带 SNI；alpn: 第一个 ALPN 协议。
func JA4(transport string, version uint16, hasSNI bool, ciphers, extensions, sigAlgs []uint16, alpn string) string {
	proto := transport
	if proto == "" {
		proto = "t"
	}
	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}
	cs := toHex4(ciphers)
	ex := toHex4(extensions)
	sa := toHex4(sigAlgs)
	alpnCode := "00"
	if len(alpn) >= 2 {
		// JA4 规范：取 ALPN 首字符与末字符
		alpnCode = string(alpn[0]) + string(alpn[len(alpn)-1])
	} else if len(alpn) == 1 {
		alpnCode = alpn + alpn
	}
	a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, tlsVersionName(version), sniFlag, len(cs), len(ex), alpnCode)
	b := hashHexList(cs)
	// c 段：扩展列表（不含 SNI 0x0000 与 ALPN 0x0010）+ "_" + 签名算法列表
	cRaw := strings.Join(ex, ",") + "_" + strings.Join(sa, ",")
	sum := sha256.Sum256([]byte(cRaw))
	c := hex.EncodeToString(sum[:])[:12]
	return a + "_" + b + "_" + c
}
