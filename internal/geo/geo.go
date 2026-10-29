// Package geo 判断 IP 是否属于中国大陆以外（"国外主机"）。
//
// 为什么需要它：拓扑里"国外主机标红"是一个强告警——红色意味着"这台机器
// 大概率有问题"。而判断"国外"必须有一份可靠的中国地址段表，没有表就只能猜，
// 而红色误标（把 114.114.114.114 标成国外）比不标更糟：用户第一次发现红点
// 是假的，之后就再也不敢信这张图了。
//
// 数据来源：`internal/geo/data/cn_ipv4.txt`（由 scripts/gen-cn-ip.py 生成，
// 见该脚本头部的获取方式与完整性自检）。运行时解析成有序区间，二分查找，
// 不引入第三方依赖、不做网络查询。
//
// 边界（必须如实告知调用方）：
//   - 只覆盖 IPv4。IPv6 返回 known=false，不做国外判定——宁可漏标，不误标。
//   - 内网/回环/链路本地不是"国外/国内"的问题，返回 known=false。
//   - 这是"注册地"而不是"物理位置"：跨国公司的自有段可能注册在境外却部署在境内。
package geo

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/cn_ipv4.txt
var cnRaw string

// span 闭区间 [lo, hi]（主机序整数）。
type span struct {
	lo uint32
	hi uint32
}

var (
	once  sync.Once
	spans []span
	stat  Stat
)

// Stat 数据状态，用于在界面上如实交代"这份判定依据有多新、覆盖多少"。
type Stat struct {
	Ranges   int    `json:"ranges"`   // 合并后的区间数
	Source   string `json:"source"`   // 数据来源描述
	LoadErr  string `json:"load_err"` // 解析失败原因（为空表示正常）
	TopRange string `json:"top_range"`
}

// load 解析嵌入数据（惰性，只做一次）。
func load() {
	lines := strings.Split(cnRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			if stat.Source == "" && strings.Contains(line, "来源") {
				stat.Source = strings.TrimPrefix(line, "#")
			}
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		lo, err1 := strconv.ParseUint(parts[0], 10, 32)
		hi, err2 := strconv.ParseUint(parts[1], 10, 32)
		if err1 != nil || err2 != nil || hi < lo {
			continue
		}
		spans = append(spans, span{lo: uint32(lo), hi: uint32(hi)})
	}
	if len(spans) == 0 {
		stat.LoadErr = "嵌入的中国地址段数据为空或格式错误"
		return
	}
	stat.Ranges = len(spans)
	stat.TopRange = uint32ToIP(spans[len(spans)-1].hi)
}

// Info 返回数据状态（/api/geo 暴露，便于用户核对判定依据）。
func Info() Stat {
	once.Do(load)
	return stat
}

// IsOverseas 判断 IP 是否属于中国大陆以外。
//
// 返回 (overseas, known)：
//   - known=false：没有依据（内网地址、IPv6、无法解析、数据未加载），
//     调用方**不应**据此标红；
//   - known=true 且 overseas=true：确认不属于中国段。
//
// 参数允许带 "/24" 后缀（拓扑的外部聚合节点就是这么存的）。
func IsOverseas(ip string) (overseas bool, known bool) {
	once.Do(load)
	if stat.LoadErr != "" {
		return false, false
	}
	v, ok := parseIPv4(ip)
	if !ok {
		return false, false
	}
	if isNonPublic(v) {
		return false, false
	}
	return !contains(v), true
}

// parseIPv4 把 "1.2.3.4" 或 "1.2.3.0/24" 解析成主机序整数；非 IPv4 返回 false。
func parseIPv4(ip string) (uint32, bool) {
	ip = strings.TrimSpace(ip)
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	if strings.ContainsRune(ip, ':') { // IPv6（含 IPv4-mapped 的冒号形式）
		return 0, false
	}
	var parts [4]uint32
	n := 0
	cur := -1
	for i := 0; i < len(ip); i++ {
		c := ip[i]
		if c == '.' {
			if n >= 3 || cur < 0 || cur > 255 {
				return 0, false
			}
			parts[n] = uint32(cur)
			n++
			cur = -1
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		if cur < 0 {
			cur = 0
		}
		cur = cur*10 + int(c-'0')
		if cur > 255 {
			return 0, false
		}
	}
	if n != 3 || cur < 0 {
		return 0, false
	}
	parts[3] = uint32(cur)
	return parts[0]<<24 | parts[1]<<16 | parts[2]<<8 | parts[3], true
}

// isNonPublic 判断是否属于不该做归属判定的地址（私网/回环/链路本地/组播/保留）。
func isNonPublic(v uint32) bool {
	switch {
	case v>>24 == 10: // 10/8
		return true
	case v>>16 == 0xC0A8: // 192.168/16
		return true
	case v>>20 == 0xAC1: // 172.16/12
		return true
	case v>>24 == 127: // 127/8
		return true
	case v>>24 == 0: // 0/8
		return true
	case v >= 0xE0000000: // 组播 224/4 + 保留 240/4
		return true
	case v>>16 == 0xA9FE: // 169.254/16
		return true
	case v >= 0x64400000 && v <= 0x647FFFFF: // 100.64/10 CGNAT
		return true
	}
	return false
}

// contains 二分查找是否落在中国段内。
func contains(v uint32) bool {
	lo, hi := 0, len(spans)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		s := spans[mid]
		switch {
		case v < s.lo:
			hi = mid - 1
		case v > s.hi:
			lo = mid + 1
		default:
			return true
		}
	}
	return false
}

// uint32ToIP 把整数还原成点分十进制（仅用于状态展示）。
func uint32ToIP(v uint32) string {
	return strconv.Itoa(int(v>>24)) + "." + strconv.Itoa(int((v>>16)&0xff)) + "." +
		strconv.Itoa(int((v>>8)&0xff)) + "." + strconv.Itoa(int(v&0xff))
}
