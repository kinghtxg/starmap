package detect

import (
	"net"
	"strconv"
	"strings"

	"starmap/internal/model"
)

// MatchAnyWhitelist 判断事件是否命中任一白名单条目（SPEC §5：命中则不产生事件）。
// 四种 kind：cidr / ip / host / node。
func MatchAnyWhitelist(entries []model.WhitelistEntry, ev *model.RiskEvent, node *model.Node) bool {
	for _, w := range entries {
		if MatchWhitelist(w, ev, node) {
			return true
		}
	}
	return false
}

// MatchWhitelist 单条匹配。
func MatchWhitelist(w model.WhitelistEntry, ev *model.RiskEvent, node *model.Node) bool {
	switch strings.ToLower(w.Kind) {
	case "node":
		// 按节点 ID（字符串形式）匹配
		if w.Value == strconv.FormatInt(ev.NodeID, 10) {
			return true
		}
	case "ip":
		if node != nil {
			for _, ip := range node.IPs {
				if ip == w.Value {
					return true
				}
			}
		}
		// 兜底：证据中的 IP 字段
		for _, k := range []string{"src_ip", "dst_ip", "ip"} {
			if ev.Evidence[k] == w.Value {
				return true
			}
		}
	case "cidr":
		_, ipnet, err := net.ParseCIDR(w.Value)
		if err != nil {
			return false
		}
		if node != nil {
			for _, ip := range node.IPs {
				if ipnet.Contains(net.ParseIP(ip)) {
					return true
				}
			}
		}
		for _, k := range []string{"src_ip", "dst_ip", "ip"} {
			if ipnet.Contains(net.ParseIP(ev.Evidence[k])) {
				return true
			}
		}
	case "host":
		v := strings.ToLower(w.Value)
		for _, k := range []string{"host", "sni", "http_host"} {
			h := strings.ToLower(ev.Evidence[k])
			if h == v || (v != "" && strings.HasSuffix(h, "."+v)) {
				return true
			}
		}
		// host 列表类证据（逗号/空白分隔）
		for _, k := range []string{"hosts", "snis"} {
			for _, h := range strings.FieldsFunc(ev.Evidence[k], func(r rune) bool {
				return r == ',' || r == ' ' || r == ';'
			}) {
				h = strings.ToLower(strings.TrimSpace(h))
				if h == v || (v != "" && strings.HasSuffix(h, "."+v)) {
					return true
				}
			}
		}
	}
	return false
}
