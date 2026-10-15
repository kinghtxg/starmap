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

// matchNodeDimension 白名单 node 维度匹配（P0-2）。
//
// 取值优先按节点稳定身份 NodeKey 匹配（review.go 误报自动加白写入的就是 NodeKey）：
// NodeKey 为 mac:<mac>（有 MAC）或 ip:<主 IP>（无 MAC），跨进程重启不变，
// 不会像内存自增 node_id 那样重启后指向另一个节点而"静默加白"。
//
// 向后兼容：V1.0 写入的旧条目形如 node:<数字 node_id>，此处仍然识别。
// 由于节点已持久化并在启动时按原 ID 恢复（topology.Engine.AttachStore），
// 同一节点重启后 ID 不变，旧条目依旧命中，不会静默失配。
// 迁移方式：运维可在白名单页把 node:<数字> 改写为 node:<mac:xx:xx...>（即节点详情里的 node_key），
// 或删除旧条目后重新走"误报复核"自动生成 NodeKey 条目。
func matchNodeDimension(value string, ev *model.RiskEvent, node *model.Node) bool {
	if node != nil && node.NodeKey != "" && value == node.NodeKey {
		return true
	}
	return value == strconv.FormatInt(ev.NodeID, 10)
}

// MatchWhitelist 单条匹配。
func MatchWhitelist(w model.WhitelistEntry, ev *model.RiskEvent, node *model.Node) bool {
	switch strings.ToLower(w.Kind) {
	case "node":
		if matchNodeDimension(w.Value, ev, node) {
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
