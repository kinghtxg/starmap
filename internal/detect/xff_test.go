package detect

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// mkXFF 构造一条带转发头的内网会话（源侧即转发节点）。
func mkXFF(srcIP, dstIP, xff0, xreal string) *model.Session {
	s := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: srcIP, DstIP: dstIP, SrcPort: 40000, DstPort: 80, Proto: "tcp"},
		MAC:       "aa:bb:cc:11:00:01",
		FirstSeen: base, LastSeen: base.Add(10 * time.Second),
		BytesUp: 2000, BytesDown: 5000, Packets: 30,
		XRealIP: xreal,
	}
	if xff0 != "" {
		s.XFF = []string{xff0}
		s.RealClientIP = xff0
		s.ProxyHops = 1
	}
	if xreal != "" && xff0 == "" {
		s.RealClientIP = xreal
	}
	return s
}

func evalSpoof(t *testing.T, ss ...*model.Session) []model.RiskEvent {
	t.Helper()
	d, eng, _ := newTestDetector(t, fullCfg())
	var list []model.Session
	for _, s := range ss {
		eng.Ingest(s)
		list = append(list, *s)
	}
	return evalXFFSpoof(&ruleContext{d: d, sessions: list, now: base.Add(time.Hour)})
}

// TestXFFSpoofSelfDeclared XFF 首跳 == 观测源：请求声称来自自己，正常代理不会这样写。
func TestXFFSpoofSelfDeclared(t *testing.T) {
	evs := evalSpoof(t, mkXFF("10.0.0.100", "10.0.0.200", "10.0.0.100", ""))
	if len(evs) != 1 {
		t.Fatalf("事件数=%d 期望 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Type != model.EventTypeXFFSpoof || ev.Level != model.RiskMid {
		t.Fatalf("事件类型/等级不对: %+v", ev)
	}
	if ev.Evidence["reason"] != "self_declared" {
		t.Fatalf("判定依据=%q", ev.Evidence["reason"])
	}
}

// TestXFFSpoofHeaderConflict X-Real-IP 与 XFF 首跳矛盾。
func TestXFFSpoofHeaderConflict(t *testing.T) {
	evs := evalSpoof(t, mkXFF("10.0.0.100", "10.0.0.200", "10.0.0.5", "10.0.0.6"))
	if len(evs) != 1 {
		t.Fatalf("事件数=%d 期望 1", len(evs))
	}
	if evs[0].Evidence["reason"] != "header_conflict" {
		t.Fatalf("判定依据=%q", evs[0].Evidence["reason"])
	}
}

// TestXFFSpoofClean 正常的转发链（XFF 与 X-Real-IP 一致、且不等于观测源）不产出事件。
func TestXFFSpoofClean(t *testing.T) {
	if evs := evalSpoof(t, mkXFF("10.0.0.100", "10.0.0.200", "10.0.0.5", "10.0.0.5")); len(evs) != 0 {
		t.Fatalf("正常转发不应告警: %+v", evs)
	}
	// 完全没有转发头的会话也不应告警
	if evs := evalSpoof(t, mkXFF("10.0.0.100", "10.0.0.200", "", "")); len(evs) != 0 {
		t.Fatalf("无 XFF 不应告警: %+v", evs)
	}
}

// TestXFFSpoofPublicSourceIgnored 公网侧不做定性（内网判定之外）。
func TestXFFSpoofPublicSourceIgnored(t *testing.T) {
	if evs := evalSpoof(t, mkXFF("203.0.113.9", "10.0.0.200", "203.0.113.9", "")); len(evs) != 0 {
		t.Fatalf("公网源不应产出事件: %+v", evs)
	}
}
