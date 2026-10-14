package review

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
	"starmap/internal/topology"
)

func setup(t *testing.T) (*Reviewer, *store.Store, *topology.Engine) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := topology.New(model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
	})
	return New(st, eng), st, eng
}

// mkEventWithNode 建一个关联真实节点的 pending 事件。
func mkEventWithNode(t *testing.T, st *store.Store, eng *topology.Engine) *model.RiskEvent {
	t.Helper()
	eng.Ingest(&model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "192.168.1.10", DstIP: "203.0.113.7", SrcPort: 1234, DstPort: 443, Proto: "tcp"},
		MAC:       "aa:bb:cc:dd:ee:01",
		FirstSeen: time.Now(), LastSeen: time.Now(),
		BytesUp: 5000, BytesDown: 5000, Packets: 30,
	})
	n := eng.NodeByIP("192.168.1.10")
	if n == nil {
		t.Fatal("节点应存在")
	}
	ev := &model.RiskEvent{
		Type: model.EventTypeFRP, NodeID: n.ID, Title: "t", Level: model.RiskMid,
		Evidence: map[string]string{"src_ip": "192.168.1.10"},
	}
	id, err := st.CreateEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.ID = id
	return ev
}

func TestReviewConfirm(t *testing.T) {
	r, st, eng := setup(t)
	ev := mkEventWithNode(t, st, eng)
	got, err := r.Review(ev.ID, ActionConfirm, "确认是内网穿透", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.EventStatusConfirmed || got.ReviewNote != "确认是内网穿透" || got.Reviewer != "admin" {
		t.Fatalf("confirm 状态流转错误: %+v", got)
	}
	logs, _ := st.ListAuditLogs(10)
	if len(logs) == 0 || logs[0].Action != "event_confirm" || logs[0].Actor != "admin" {
		t.Fatalf("缺少 confirm 审计留痕: %+v", logs)
	}
}

func TestReviewFalsePositiveAutoWhitelist(t *testing.T) {
	r, st, eng := setup(t)
	ev := mkEventWithNode(t, st, eng)
	got, err := r.Review(ev.ID, ActionFalsePositive, "是办公 VPN", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.EventStatusFalsePositive {
		t.Fatalf("状态应为 false_positive，实际 %s", got.Status)
	}
	// 自动加白：node + ip 两个维度
	wl, _ := st.ListWhitelist()
	hasNode, hasIP := false, false
	for _, w := range wl {
		if w.Kind == "node" && w.Value == fmt.Sprintf("%d", ev.NodeID) {
			hasNode = true
		}
		if w.Kind == "ip" && w.Value == "192.168.1.10" {
			hasIP = true
		}
	}
	if !hasNode || !hasIP {
		t.Fatalf("应自动加白 node+ip 维度: %+v", wl)
	}
	// 节点风险回退
	if n := eng.GetNode(ev.NodeID); n.RiskLevel != model.RiskNone {
		t.Fatalf("误报后节点风险应回退 none，实际 %s", n.RiskLevel)
	}
	// 审计：加白 + 误报操作
	logs, _ := st.ListAuditLogs(20)
	if len(logs) < 3 {
		t.Fatalf("审计留痕不足: %+v", logs)
	}
}

func TestReviewDefer(t *testing.T) {
	r, st, eng := setup(t)
	ev := mkEventWithNode(t, st, eng)
	got, err := r.Review(ev.ID, ActionDefer, "稍后看", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.EventStatusDeferred || got.Reviewer != "system" {
		t.Fatalf("defer 流转错误: %+v", got)
	}
}

func TestReviewInvalidAndNotFound(t *testing.T) {
	r, st, eng := setup(t)
	ev := mkEventWithNode(t, st, eng)
	if _, err := r.Review(ev.ID, "delete", "", ""); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("非法动作应返回 ErrInvalidAction，实际 %v", err)
	}
	if _, err := r.Review(9999, ActionConfirm, "", ""); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("不存在事件应返回 ErrEventNotFound，实际 %v", err)
	}
}

func TestSuppressByWhitelist(t *testing.T) {
	r, st, eng := setup(t)
	ev := mkEventWithNode(t, st, eng)
	// 新增 ip 白名单 → 已有 pending 事件自动 false_positive
	n, err := r.SuppressByWhitelist(model.WhitelistEntry{Kind: "ip", Value: "192.168.1.10"}, "api")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应抑制 1 个事件，实际 %d", n)
	}
	got, _ := st.GetEvent(ev.ID)
	if got.Status != model.EventStatusFalsePositive {
		t.Fatalf("事件应自动转 false_positive，实际 %s", got.Status)
	}
	// 不命中则不动
	ev2 := &model.RiskEvent{Type: model.EventTypeClash, NodeID: ev.NodeID, Title: "t2", Level: model.RiskMid, Evidence: map[string]string{}}
	id2, _ := st.CreateEvent(ev2)
	n, _ = r.SuppressByWhitelist(model.WhitelistEntry{Kind: "host", Value: "nomatch.example"}, "api")
	if n != 0 {
		t.Fatal("不命中不应抑制")
	}
	got2, _ := st.GetEvent(id2)
	if got2.Status != model.EventStatusPending {
		t.Fatal("不命中事件应保持 pending")
	}
}
