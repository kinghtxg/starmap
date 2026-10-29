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

// MatchNodeWhitelist 判断**节点本身**是否被白名单覆盖（不看事件）。
//
// 为什么需要单独一个入口：事件侧的白名单解决"这件事不再报"，但拓扑视图要回答的是
// "这台设备还要不要标红外置"。二者判据应该一致——用户在白名单里加了一条 IP/CIDR，
// 期望的是"这台设备是已知已知资产，别再给我标红"，而不是只去掉某一条事件。
//
// 只认 node/ip/cidr 三种 kind：host 维度是域名，天然对不上一个设备；
// 事件相关的证据字段这里没有也不该有。
func MatchNodeWhitelist(entries []model.WhitelistEntry, node *model.Node) bool {
	if node == nil {
		return false
	}
	for _, w := range entries {
		switch strings.ToLower(w.Kind) {
		case "node":
			if node.NodeKey != "" && w.Value == node.NodeKey {
				return true
			}
			// 兼容 V1.0 的 node:<数字 id> 条目
			if w.Value == strconv.FormatInt(node.ID, 10) {
				return true
			}
		case "ip":
			for _, ip := range node.IPs {
				if ip == w.Value {
					return true
				}
			}
		case "cidr":
			_, ipnet, err := net.ParseCIDR(w.Value)
			if err != nil {
				continue
			}
			for _, ip := range node.IPs {
				// 外部聚合节点存的是 "8.8.8.0/24"，先取网络地址再做包含判断，
				// 否则 net.ParseIP 直接返回 nil，"白名单一条 /24"永远不生效。
				if i := strings.IndexByte(ip, '/'); i >= 0 {
					ip = ip[:i]
				}
				if ipnet.Contains(net.ParseIP(ip)) {
					return true
				}
			}
		}
	}
	return false
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
