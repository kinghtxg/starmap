package agent

import (
	"time"

	"starmap/internal/model"
)

// Flow 探针上报的会话。字段名必须与服务端 internal/api 的 probeFlow 完全一致——
// 两侧是各自解耦的结构体，靠 JSON 字段名对齐，改任何一边都要同步改另一边。
type Flow struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Proto     string `json:"proto"`
	MAC       string `json:"mac,omitempty"`
	DstMAC    string `json:"dst_mac,omitempty"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Packets   int64  `json:"packets"`

	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`

	SNI      string `json:"sni,omitempty"`
	HTTPHost string `json:"http_host,omitempty"`
	JA3      string `json:"ja3,omitempty"`
	JA4      string `json:"ja4,omitempty"`

	// 设备身份证据（V1.5）：探针是最靠近设备的观测点，它看到的这三样东西
	// 一旦不往上报，服务端就只能靠端口猜设备类型——TTL 决定系统栈大类，
	// UA / Server 头直接说出跑的是什么软件。都是会话级元数据，不增加流量。
	StartTTL   int    `json:"start_ttl,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	HTTPServer string `json:"http_server,omitempty"`

	IsLongConn          bool  `json:"is_long_conn,omitempty"`
	HeartbeatIntervalMs int64 `json:"heartbeat_interval_ms,omitempty"`

	Location string   `json:"location,omitempty"`
	XFF      []string `json:"xff,omitempty"`
	XRealIP  string   `json:"x_real_ip,omitempty"`
}

// MapSessions 把聚合器产出的会话转成上报结构。
//
// 刻意保留 SNI / JA3 / JA4 / XFF：这些指纹是探针侧最有价值的部分，
// 一旦在聚合或编码环节丢掉，服务端的 frp / clash / reverse_proxy 规则会全部失效，
// 而且表现为"探针在跑、拓扑也有，就是不报警"——排查成本极高。
func MapSessions(sessions []model.Session) []Flow {
	out := make([]Flow, 0, len(sessions))
	for i := range sessions {
		s := &sessions[i]
		if s.FiveTuple.SrcIP == "" || s.FiveTuple.DstIP == "" {
			continue
		}
		proto := s.FiveTuple.Proto
		if proto == "" {
			proto = "tcp"
		}
		out = append(out, Flow{
			SrcIP:     s.FiveTuple.SrcIP,
			DstIP:     s.FiveTuple.DstIP,
			SrcPort:   s.FiveTuple.SrcPort,
			DstPort:   s.FiveTuple.DstPort,
			Proto:     proto,
			MAC:       s.MAC,
			DstMAC:    s.DstMAC,
			BytesUp:   s.BytesUp,
			BytesDown: s.BytesDown,
			Packets:   s.Packets,

			FirstSeen: s.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:  s.LastSeen.UTC().Format(time.RFC3339),

			SNI:      s.SNI,
			HTTPHost: s.HTTPHost,
			JA3:      s.JA3,
			JA4:      s.JA4,

			StartTTL:   s.StartTTL,
			UserAgent:  s.UserAgent,
			HTTPServer: s.HTTPServer,

			IsLongConn:          s.IsLongConn,
			HeartbeatIntervalMs: s.HeartbeatIntervalMs,

			Location: s.Location,
			XFF:      s.XFF,
			XRealIP:  s.XRealIP,
		})
	}
	return out
}
