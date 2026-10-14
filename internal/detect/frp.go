package detect

import (
	"fmt"
	"strconv"
	"strings"

	"starmap/internal/model"
)

// Go-TLS 客户端指纹表（自维护，启发式）。
// JA3 收录公开的 Go crypto/tls 客户端常见哈希；JA4 按前缀匹配
// （Go 客户端典型为 TLS1.3、15~17 个 cipher、ALPN h2 等特征组合）。
// 注意：仅用于"打标签"，不构成定性结论。
var goTLSJA3 = map[string]bool{
	// Go crypto/tls 默认 ClientHello 的常见 JA3（社区公开观测值）
	"fd8b3113a5a6c8c9f8b07b4e80b04d0e": true,
	"3b5074b1b5d032e25fba0e3a1b62c257": true,
	"6734f37431670b3ab4292b8f60f29984": true,
}

var goTLSJA4Prefixes = []string{
	"t13d1516h2", // TLS1.3 / 15 ciphers / 16 exts / ALPN h2（Go 典型）
	"t13d1517h2",
	"t13d1715h2",
	"t13d151600", // 无 ALPN 的 Go 客户端
}

// matchGoTLS 判定 JA3/JA4 是否匹配 Go-TLS 客户端指纹表。
func matchGoTLS(ja3, ja4 string) bool {
	if ja3 != "" && goTLSJA3[ja3] {
		return true
	}
	for _, p := range goTLSJA4Prefixes {
		if strings.HasPrefix(ja4, p) {
			return true
		}
	}
	return false
}

// evalFRP FRP 三重校验（SPEC §5）：
//  1. JA3/JA4 匹配 Go-TLS 客户端指纹表
//  2. TCP 连接时长 > longConnSeconds（默认 1h）且保活
//  3. 周期性小包心跳（间隔方差小，payload < 64B，由聚合器判定）
//
// 三中二 → mid；三中三 → high。
func evalFRP(rc *ruleContext) []model.RiskEvent {
	longConn := rc.d.Cfg.LongConnSeconds
	if longConn <= 0 {
		longConn = 3600
	}
	var out []model.RiskEvent
	for i := range rc.sessions {
		s := &rc.sessions[i]
		if s.FiveTuple.Proto != "tcp" {
			continue
		}
		node := rc.internalNodeOf(s)
		if node == nil {
			continue
		}

		hitJA := matchGoTLS(s.JA3, s.JA4)
		hitLong := s.IsLongConn || sessionDuration(s).Seconds() > float64(longConn)
		hitHeartbeat := s.HeartbeatIntervalMs > 0

		score := 0
		for _, h := range []bool{hitJA, hitLong, hitHeartbeat} {
			if h {
				score++
			}
		}
		if score < 2 {
			continue
		}
		level := model.RiskMid
		if score == 3 {
			level = model.RiskHigh
		}
		peer := publicPeerOf(s)
		if peer == "" {
			peer = s.FiveTuple.DstIP
		}
		out = append(out, model.RiskEvent{
			Type:   model.EventTypeFRP,
			NodeID: node.ID,
			Level:  level,
			Title:  fmt.Sprintf("疑似 FRP 隧道特征（命中 %d/3 项）", score),
			Detail: fmt.Sprintf("节点 %s 与 %s:%d 的 TCP 会话呈现 FRP 特征组合（仅标签，非定性）",
				firstIP(node), peer, s.FiveTuple.DstPort),
			Evidence: map[string]string{
				"ja3":                   s.JA3,
				"ja4":                   s.JA4,
				"ja_match":              strconv.FormatBool(hitJA),
				"long_conn":             strconv.FormatBool(hitLong),
				"duration_sec":          strconv.FormatInt(int64(sessionDuration(s).Seconds()), 10),
				"heartbeat_interval_ms": strconv.FormatInt(s.HeartbeatIntervalMs, 10),
				"heartbeat":             strconv.FormatBool(hitHeartbeat),
				"src_ip":                s.FiveTuple.SrcIP,
				"dst_ip":                s.FiveTuple.DstIP,
				"dst_port":              strconv.Itoa(int(s.FiveTuple.DstPort)),
			},
		})
	}
	return out
}

func firstIP(n *model.Node) string {
	if n != nil && len(n.IPs) > 0 {
		return n.IPs[0]
	}
	return "?"
}
