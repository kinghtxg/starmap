package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
	"starmap/internal/topology"
)

var base = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestDetector(t *testing.T, cfg model.SystemConfig) (*Detector, *topology.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := topology.New(cfg)
	d := New(st, eng, cfg)
	d.LearningPeriod = 0                                        // 测试默认跳过学习期（未知出口用例单独控制）
	d.NowFunc = func() time.Time { return base.Add(time.Hour) } // 固定时钟，贴近构造会话时间
	return d, eng, st
}

func fullCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
		ReverseProxyHosts: 10, LongConnSeconds: 3600, HeartbeatMaxBytes: 64,
	}
}

// 多会话场景下的会话表
var sessionList []model.Session

func currentSessions() []model.Session { return sessionList }

func setSessions(d *Detector, eng *topology.Engine, ss ...*model.Session) {
	sessionList = nil
	for _, s := range ss {
		eng.Ingest(s)
		sessionList = append(sessionList, *s)
	}
	d.SessionsFunc = currentSessions
}

func bigSession(src, dst, mac string, port uint16, start time.Time) *model.Session {
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: src, DstIP: dst, SrcPort: port, DstPort: 443, Proto: "tcp"},
		MAC:       mac,
		FirstSeen: start, LastSeen: start.Add(10 * time.Second),
		BytesUp: 2000, BytesDown: 5000, Packets: 30,
	}
}

// ---------- FRP ----------

func frpSession(ja, longConn, heartbeat bool) *model.Session {
	s := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "192.168.1.10", DstIP: "203.0.113.50", SrcPort: 5000, DstPort: 7000, Proto: "tcp"},
		MAC:       "aa:bb:cc:10:00:01",
		FirstSeen: base, LastSeen: base.Add(10 * time.Second),
		BytesUp: 5000, BytesDown: 5000, Packets: 50,
	}
	if ja {
		s.JA4 = "t13d1516h2_8daaf6152771_b186095e22b6" // Go-TLS 指纹前缀
	}
	if longConn {
		s.LastSeen = s.FirstSeen.Add(2 * time.Hour)
		s.IsLongConn = true
	}
	if heartbeat {
		s.HeartbeatIntervalMs = 30000
	}
	return s
}

func TestFRPTwoOfThree(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	setSessions(d, eng, frpSession(true, true, false))
	created, err := d.Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("三中二应产生 1 个事件，实际 %d", len(created))
	}
	ev := created[0]
	if ev.Type != model.EventTypeFRP || ev.Level != model.RiskMid || ev.Status != model.EventStatusPending {
		t.Fatalf("事件字段错误: %+v", ev)
	}
	if ev.Evidence["ja4"] == "" {
		t.Fatal("证据应含 JA4")
	}
	// 节点风险联动
	if n := eng.GetNode(ev.NodeID); n.RiskLevel != model.RiskMid {
		t.Fatalf("节点风险应为 mid，实际 %s", n.RiskLevel)
	}
	_ = st
}

func TestFRPThreeOfThree(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	setSessions(d, eng, frpSession(true, true, true))
	created, _ := d.Evaluate()
	if len(created) != 1 || created[0].Level != model.RiskHigh {
		t.Fatalf("三中三应为 high，实际 %+v", created)
	}
}

func TestFRPOneOfThree(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	setSessions(d, eng, frpSession(false, true, false)) // 仅长连接
	created, _ := d.Evaluate()
	if len(created) != 0 {
		t.Fatalf("仅一项命中不应产生事件: %+v", created)
	}
	if evs, _ := st.ListEvents("", ""); len(evs) != 0 {
		t.Fatal("库中不应有事件")
	}
}

func TestFRPNonTCP(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	s := frpSession(true, true, true)
	s.FiveTuple.Proto = "udp"
	setSessions(d, eng, s)
	created, _ := d.Evaluate()
	if len(created) != 0 {
		t.Fatal("UDP 会话不参与 FRP 判定")
	}
}

// ---------- Clash ----------

func TestClashTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	var ss []*model.Session
	// 10 个短会话、5 个不同公网 /24、随机 SNI
	for i := 0; i < 10; i++ {
		s := bigSession("192.168.1.10", fmt.Sprintf("203.0.%d.9", i/2), "aa:bb:cc:20:00:01", uint16(6000+i), base)
		s.BytesUp, s.BytesDown = 1000, 1000
		if i < 3 {
			s.SNI = fmt.Sprintf("x9q8w7e6r5t4z%d.com", i) // 随机主标签
		}
		ss = append(ss, s)
	}
	setSessions(d, eng, ss...)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeClash {
			found = true
			if ev.Level != model.RiskMid {
				t.Fatalf("clash 应为 mid，实际 %s", ev.Level)
			}
		}
	}
	if !found {
		t.Fatal("应产生 clash 事件")
	}
}

func TestClashNoTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	var ss []*model.Session
	for i := 0; i < 10; i++ {
		s := bigSession("192.168.1.10", fmt.Sprintf("203.0.%d.9", i/2), "aa:bb:cc:20:00:02", uint16(6100+i), base)
		s.SNI = fmt.Sprintf("www.example%d.com", i) // 正常域名
		ss = append(ss, s)
	}
	setSessions(d, eng, ss...)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeClash {
			t.Fatal("正常域名不应触发 clash")
		}
	}
}

func TestClashHighDistinct(t *testing.T) {
	// 陌生目的 /24 数 ≥ 20 → 升级 high
	d, eng, _ := newTestDetector(t, fullCfg())
	var ss []*model.Session
	for i := 0; i < 24; i++ {
		// 24 个不同的公网 /24
		s := bigSession("192.168.1.10", fmt.Sprintf("198.%d.%d.9", i, i), "aa:bb:cc:20:00:03", uint16(6200+i), base)
		s.SNI = fmt.Sprintf("x9q8w7e6r5t4z%d.com", i) // 随机主标签（≥10 字符高熵）
		ss = append(ss, s)
	}
	setSessions(d, eng, ss...)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeClash {
			found = true
			if ev.Level != model.RiskHigh {
				t.Fatalf("陌生目的 ≥20 应升级 high，实际 %s", ev.Level)
			}
		}
	}
	if !found {
		t.Fatal("应产生 clash high 事件")
	}
}

func TestLooksRandomSNI(t *testing.T) {
	if !looksRandomSNI("x9q8w7e6r5t4z3y2x1w0v.com") {
		t.Fatal("高熵随机主标签应判定为随机 SNI")
	}
	if looksRandomSNI("www.example.com") {
		t.Fatal("正常域名不应判定为随机 SNI")
	}
	if looksRandomSNI("short.com") {
		t.Fatal("短标签不应判定为随机 SNI")
	}
	if looksRandomSNI("") {
		t.Fatal("空 SNI 不应判定")
	}
}

// ---------- 反代 ----------

func rpSessions(n int) []*model.Session {
	var ss []*model.Session
	for i := 0; i < n; i++ {
		s := bigSession("192.168.1.10", fmt.Sprintf("198.51.100.%d", i+1), "aa:bb:cc:30:00:01", uint16(7000+i), base)
		s.HTTPHost = fmt.Sprintf("site%d.example.com", i)
		ss = append(ss, s)
	}
	return ss
}

func TestReverseProxyTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg()) // 阈值 10
	setSessions(d, eng, rpSessions(11)...)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeReverseProxy {
			found = true
		}
	}
	if !found {
		t.Fatal("Host 数 11 > 阈值 10 应触发")
	}
}

func TestReverseProxyNoTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	setSessions(d, eng, rpSessions(10)...)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeReverseProxy {
			t.Fatal("Host 数 10 ≤ 阈值 10 不应触发")
		}
	}
}

func TestReverseProxyThresholdConfig(t *testing.T) {
	cfg := fullCfg()
	cfg.ReverseProxyHosts = 3 // 阈值调低应触发
	d, eng, _ := newTestDetector(t, cfg)
	setSessions(d, eng, rpSessions(4)...)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeReverseProxy {
			found = true
		}
	}
	if !found {
		t.Fatal("阈值调为 3 后 4 个 Host 应触发")
	}
}

// ---------- 未知出口 ----------

func TestUnknownEgress(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	// 第一轮：基线 2 条对外链路
	setSessions(d, eng,
		bigSession("192.168.1.10", "203.0.113.1", "aa:bb:cc:40:00:01", 8001, base),
		bigSession("192.168.1.10", "203.0.113.2", "aa:bb:cc:40:00:01", 8002, base),
	)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeUnknownEgress {
			t.Fatal("基线建立轮不应触发")
		}
	}
	// 第二轮：突增到 25 条 > max(3×2, 20)
	var ss []*model.Session
	for i := 0; i < 25; i++ {
		s := bigSession("192.168.1.10", fmt.Sprintf("203.0.113.%d", i+1), "aa:bb:cc:40:00:01", uint16(8100+i), base)
		s.FiveTuple.DstPort = uint16(1000 + i)
		ss = append(ss, s)
	}
	setSessions(d, eng, ss...)
	created, _ = d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeUnknownEgress {
			found = true
		}
	}
	if !found {
		t.Fatal("链路数突增应触发 unknown_egress")
	}
}

func TestUnknownEgressLearningPeriod(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	d.LearningPeriod = time.Hour // 学习期内
	var ss []*model.Session
	for i := 0; i < 30; i++ {
		s := bigSession("192.168.1.10", fmt.Sprintf("203.0.113.%d", i+1), "aa:bb:cc:40:00:09", uint16(8200+i), base)
		s.FiveTuple.DstPort = uint16(2000 + i)
		ss = append(ss, s)
	}
	setSessions(d, eng, ss...)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeUnknownEgress {
			t.Fatal("学习期内不应产出 unknown_egress 事件")
		}
	}
}

// ---------- 多网域融合 ----------

func TestMultiNet(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{
		{Name: "gov", CIDRs: []string{"10.0.0.0/8"}},
		{Name: "prod", CIDRs: []string{"192.168.0.0/16"}},
	})
	st.CreateDomain(&model.NetDomain{Name: "gov", CIDRs: []string{"10.0.0.0/8"}})
	st.CreateDomain(&model.NetDomain{Name: "prod", CIDRs: []string{"192.168.0.0/16"}})
	// 同节点跨两个内网域：192.168.1.10(prod) → 10.9.9.9(gov) + → 192.168.3.3(prod)
	setSessions(d, eng,
		bigSession("192.168.1.10", "10.9.9.9", "aa:bb:cc:50:00:01", 9001, base),
		bigSession("192.168.1.10", "192.168.3.3", "aa:bb:cc:50:00:01", 9002, base),
	)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type == model.EventTypeMultiNet {
			found = true
			if ev.Level != model.RiskHigh {
				t.Fatalf("multi_net 应为 high，实际 %s", ev.Level)
			}
		}
	}
	if !found {
		t.Fatal("跨 ≥2 网络域应产生 multi_net high 事件")
	}
}

// 政务网核心场景（V1.4）：同一台设备（同 MAC）跨 /24 网段，但落在同一个大域内。
// 旧实现只按 NetDomain（192.168.0.0/16）判定 → 同域内跨网段完全漏检。
// 改为按流量自动归纳的实际网段判定后必须能检出（"一机两网"）。
func TestMultiNetSameDomainCrossSubnet(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{
		{Name: "prod", CIDRs: []string{"192.168.0.0/16"}},
	})
	st.CreateDomain(&model.NetDomain{Name: "prod", CIDRs: []string{"192.168.0.0/16"}})
	// 同一 MAC 分别出现在 192.168.1.x 与 192.168.2.x 两个 /24 网段
	setSessions(d, eng,
		bigSession("192.168.1.5", "8.8.8.8", "aa:bb:cc:60:00:01", 9201, base),
		bigSession("192.168.2.10", "8.8.8.8", "aa:bb:cc:60:00:01", 9202, base),
	)
	created, _ := d.Evaluate()
	found := false
	for _, ev := range created {
		if ev.Type != model.EventTypeMultiNet {
			continue
		}
		found = true
		if ev.Level != model.RiskHigh {
			t.Fatalf("multi_net 应为 high，实际 %s", ev.Level)
		}
		if !strings.Contains(ev.Evidence["basis"], "subnet") {
			t.Fatalf("应按网段维度(basis 含 subnet)判定，实际 basis=%q", ev.Evidence["basis"])
		}
		if !strings.Contains(ev.Evidence["subnets"], "192.168.1.0/24") ||
			!strings.Contains(ev.Evidence["subnets"], "192.168.2.0/24") {
			t.Fatalf("subnets 应包含两个 /24 网段，实际 %q", ev.Evidence["subnets"])
		}
	}
	if !found {
		t.Fatal("同一 MAC 跨 /24 网段（同域内）应产生 multi_net high 事件")
	}
}

// 单网段单域：不应误报
func TestMultiNetSingleSubnetNoTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{{Name: "prod", CIDRs: []string{"192.168.0.0/16"}}})
	setSessions(d, eng,
		bigSession("192.168.1.5", "8.8.8.8", "aa:bb:cc:60:00:02", 9211, base),
		bigSession("192.168.1.6", "8.8.8.8", "aa:bb:cc:60:00:02", 9212, base),
	)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeMultiNet {
			t.Fatalf("同一 /24 网段内不应触发 multi_net，实际 evidence=%v", ev.Evidence)
		}
	}
}

func TestMultiNetNoTrigger(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{{Name: "prod", CIDRs: []string{"192.168.0.0/16"}}})
	setSessions(d, eng,
		bigSession("192.168.1.10", "192.168.1.20", "aa:bb:cc:50:00:09", 9101, base),
	)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeMultiNet {
			t.Fatal("单域流量不应触发 multi_net")
		}
	}
}

// ---------- 白名单抑制 ----------

func TestWhitelistSuppression(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	// 先加白（ip 维度）
	if _, err := st.CreateWhitelistEntry(&model.WhitelistEntry{Kind: "ip", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	setSessions(d, eng, frpSession(true, true, true))
	created, _ := d.Evaluate()
	if len(created) != 0 {
		t.Fatalf("白名单命中不应产生事件: %+v", created)
	}
}

func TestWhitelistCIDRAndNode(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	st.CreateWhitelistEntry(&model.WhitelistEntry{Kind: "cidr", Value: "192.168.0.0/16"})
	setSessions(d, eng, frpSession(true, true, true))
	if created, _ := d.Evaluate(); len(created) != 0 {
		t.Fatal("CIDR 白名单应抑制")
	}

	// node 维度
	d2, eng2, st2 := newTestDetector(t, fullCfg())
	setSessions(d2, eng2, frpSession(true, true, true))
	n := eng2.NodeByIP("192.168.1.10")
	st2.CreateWhitelistEntry(&model.WhitelistEntry{Kind: "node", Value: fmt.Sprintf("%d", n.ID)})
	if created, _ := d2.Evaluate(); len(created) != 0 {
		t.Fatal("node 白名单应抑制")
	}
}

func TestWhitelistHost(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	st.CreateWhitelistEntry(&model.WhitelistEntry{Kind: "host", Value: "example.com"})
	setSessions(d, eng, rpSessions(11)...)
	created, _ := d.Evaluate()
	for _, ev := range created {
		if ev.Type == model.EventTypeReverseProxy {
			t.Fatal("host 白名单应抑制反代事件（hosts 证据匹配）")
		}
	}
}

// ---------- 事件去重（§10.5） ----------

func TestEventDedup(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	setSessions(d, eng, frpSession(true, true, true))
	created1, _ := d.Evaluate()
	if len(created1) != 1 {
		t.Fatal("第一轮应产生 1 事件")
	}
	created2, _ := d.Evaluate()
	if len(created2) != 0 {
		t.Fatal("24h 内同 (type,node) 不应重复建单")
	}
	evs, _ := st.ListEvents("", model.EventTypeFRP)
	if len(evs) != 1 {
		t.Fatalf("库中应只有 1 个事件，实际 %d", len(evs))
	}
	// 去重命中应更新 UpdatedAt（≥ CreatedAt）
	if evs[0].UpdatedAt.Before(evs[0].CreatedAt) {
		t.Fatal("UpdatedAt 应 >= CreatedAt")
	}
}
