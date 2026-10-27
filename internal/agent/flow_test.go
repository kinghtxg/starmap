package agent

import (
	"encoding/json"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestMapSessionsKeepsFingerprints 锁住探针最有价值的那部分字段。
//
// 这些字段一旦丢，服务端的 frp / clash / reverse_proxy 规则会全部静默失效：
// 探针照常在跑、拓扑照样有节点、日志一行错都没有，就是不出事件。
// 这个测试的存在意义就是让这种"静默失效"变成编译/测试期的硬失败。
func TestMapSessionsKeepsFingerprints(t *testing.T) {
	first := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	last := first.Add(90 * time.Second)
	in := []model.Session{{
		FiveTuple: model.FiveTuple{
			SrcIP: "10.1.2.3", DstIP: "203.0.113.9", SrcPort: 51234, DstPort: 443, Proto: "tcp",
		},
		MAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		FirstSeen: first, LastSeen: last,
		BytesUp: 1200, BytesDown: 34000, Packets: 42,
		SNI: "frp.example.com", HTTPHost: "", JA3: "abcdef0123456789", JA4: "t13d1516h2_8daaf6152771",
		IsLongConn: true, HeartbeatIntervalMs: 30000,
		Location: "核心镜像口",
		XFF:      []string{"198.51.100.7", "10.1.2.3"},
		XRealIP:  "198.51.100.7",
	}}

	out := MapSessions(in)
	if len(out) != 1 {
		t.Fatalf("会话数 = %d, 期望 1", len(out))
	}
	f := out[0]
	checks := []struct {
		name      string
		got, want string
	}{
		{"sni", f.SNI, "frp.example.com"},
		{"ja3", f.JA3, "abcdef0123456789"},
		{"ja4", f.JA4, "t13d1516h2_8daaf6152771"},
		{"location", f.Location, "核心镜像口"},
		{"x_real_ip", f.XRealIP, "198.51.100.7"},
		{"mac", f.MAC, "aa:bb:cc:dd:ee:ff"},
		{"dst_mac", f.DstMAC, "11:22:33:44:55:66"},
		{"first_seen", f.FirstSeen, "2026-10-27T08:00:00Z"},
		{"last_seen", f.LastSeen, "2026-10-27T08:01:30Z"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, 期望 %q", c.name, c.got, c.want)
		}
	}
	if len(f.XFF) != 2 || f.XFF[0] != "198.51.100.7" {
		t.Errorf("XFF = %v, 期望原样保序 [198.51.100.7 10.1.2.3]", f.XFF)
	}
	if !f.IsLongConn || f.HeartbeatIntervalMs != 30000 {
		t.Errorf("长连接标记丢失: long=%v hb=%d", f.IsLongConn, f.HeartbeatIntervalMs)
	}
	if f.BytesUp != 1200 || f.BytesDown != 34000 || f.Packets != 42 {
		t.Errorf("流量计数错: up=%d down=%d pkt=%d", f.BytesUp, f.BytesDown, f.Packets)
	}
}

// TestMapSessionsSkipsInvalid 没有 IP 的会话不能上报：服务端 toPackets 会直接丢掉，
// 但白占一次带宽，而且会让"上报条数"和"入库条数"对不上，排查时误导人。
func TestMapSessionsSkipsInvalid(t *testing.T) {
	in := []model.Session{
		{FiveTuple: model.FiveTuple{SrcIP: "", DstIP: "1.1.1.1"}},
		{FiveTuple: model.FiveTuple{SrcIP: "1.1.1.1", DstIP: ""}},
		{FiveTuple: model.FiveTuple{SrcIP: "1.1.1.1", DstIP: "2.2.2.2"}},
	}
	if got := len(MapSessions(in)); got != 1 {
		t.Fatalf("保留 %d 条, 期望 1", got)
	}
}

// TestMapSessionsDefaultProto 空协议按 tcp 兜底：服务端 toPackets 也是这么做的，
// 两边必须一致，否则合成报文的协议字段和服务端规则判断会分叉。
func TestMapSessionsDefaultProto(t *testing.T) {
	out := MapSessions([]model.Session{{
		FiveTuple: model.FiveTuple{SrcIP: "1.1.1.1", DstIP: "2.2.2.2"},
	}})
	if len(out) != 1 || out[0].Proto != "tcp" {
		t.Fatalf("proto = %q, 期望 tcp", out[0].Proto)
	}
}

// TestFlowJSONFieldNames 字段名是对外协议。
// 探针和服务端是两个独立结构体，靠 JSON 标签对齐；改错一个字符不会报错，
// 只会表现为某个字段永远是空值。
func TestFlowJSONFieldNames(t *testing.T) {
	b, err := json.Marshal(Flow{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2", Proto: "tcp",
		MAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SNI: "a.com", JA3: "j3", JA4: "j4", XRealIP: "9.9.9.9",
		IsLongConn: true, HeartbeatIntervalMs: 1000,
		Location: "镜像口",
		XFF:      []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	for _, k := range []string{
		"src_ip", "dst_ip", "src_port", "dst_port", "proto", "bytes_up", "bytes_down",
		"packets", "first_seen", "last_seen", "sni", "ja3", "ja4",
		"is_long_conn", "heartbeat_interval_ms", "location", "xff", "x_real_ip",
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("缺少字段 %q（服务端 probeFlow 靠这个名字取）", k)
		}
	}
}
