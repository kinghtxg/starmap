package store

import (
	"path/filepath"
	"testing"
	"time"

	"starmap/internal/model"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestNodeCRUD(t *testing.T) {
	st := openTemp(t)
	n := &model.Node{
		IPs: []string{"10.0.0.1", "10.0.0.2"}, MAC: "aa:bb:cc:dd:ee:ff",
		FirstSeen: time.Now(), LastSeen: time.Now(),
		Domain: "office", Labels: []string{"server"}, RiskLevel: model.RiskMid, Active: true,
	}
	id, err := st.CreateNode(n)
	if err != nil || id <= 0 {
		t.Fatalf("CreateNode: id=%d err=%v", id, err)
	}
	got, err := st.GetNode(id)
	if err != nil || got == nil {
		t.Fatalf("GetNode: %v", err)
	}
	if len(got.IPs) != 2 || got.MAC != n.MAC || got.RiskLevel != model.RiskMid || !got.Active {
		t.Fatalf("节点字段不匹配: %+v", got)
	}
	got.RiskLevel = model.RiskHigh
	if err := st.UpdateNode(got); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	list, err := st.ListNodes()
	if err != nil || len(list) != 1 || list[0].RiskLevel != model.RiskHigh {
		t.Fatalf("ListNodes: %v %+v", err, list)
	}
	if err := st.DeleteNode(id); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if got, _ := st.GetNode(id); got != nil {
		t.Fatal("删除后仍能查到节点")
	}
}

func TestEdgeCRUD(t *testing.T) {
	st := openTemp(t)
	e := &model.Edge{SrcID: 1, DstID: 2, Protocol: "tcp", Bytes: 100, Packets: 5,
		FirstSeen: time.Now(), LastSeen: time.Now(), Active: true}
	id, err := st.CreateEdge(e)
	if err != nil {
		t.Fatalf("CreateEdge: %v", err)
	}
	got, err := st.GetEdge(id)
	if err != nil || got.Bytes != 100 {
		t.Fatalf("GetEdge: %v %+v", err, got)
	}
	got.Active = false
	if err := st.UpdateEdge(got); err != nil {
		t.Fatalf("UpdateEdge: %v", err)
	}
	list, _ := st.ListEdges()
	if len(list) != 1 || list[0].Active {
		t.Fatalf("ListEdges: %+v", list)
	}
}

func TestSessionCRUD(t *testing.T) {
	st := openTemp(t)
	ses := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", SrcPort: 5000, DstPort: 443, Proto: "tcp"},
		MAC:       "aa:bb:cc:dd:ee:ff", StartTTL: 64,
		FirstSeen: time.Now(), LastSeen: time.Now(),
		BytesUp: 100, BytesDown: 200, Packets: 3,
		SNI: "a.com", JA3: "abc", JA4: "t13d", IsLongConn: true,
	}
	id, err := st.SaveSession(ses)
	if err != nil || id <= 0 {
		t.Fatalf("SaveSession: %v", err)
	}
	list, err := st.ListSessions()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions: %v", err)
	}
	if list[0].SNI != "a.com" || !list[0].IsLongConn || list[0].FiveTuple.SrcPort != 5000 {
		t.Fatalf("会话字段不匹配: %+v", list[0])
	}
}

func TestEventCRUDAndReview(t *testing.T) {
	st := openTemp(t)
	ev := &model.RiskEvent{
		Type: model.EventTypeFRP, NodeID: 1, Title: "疑似 FRP", Detail: "JA3 命中",
		Evidence: map[string]string{"ja3": "abc"}, Level: model.RiskMid,
	}
	id, err := st.CreateEvent(ev)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	pending, _ := st.ListEvents(model.EventStatusPending, "")
	if len(pending) != 1 {
		t.Fatalf("pending 事件数 = %d", len(pending))
	}
	if err := st.UpdateEventStatus(id, model.EventStatusConfirmed, "确认", "admin"); err != nil {
		t.Fatalf("UpdateEventStatus: %v", err)
	}
	got, _ := st.GetEvent(id)
	if got.Status != model.EventStatusConfirmed || got.Reviewer != "admin" || got.Evidence["ja3"] != "abc" {
		t.Fatalf("事件状态异常: %+v", got)
	}
	byType, _ := st.ListEvents("", model.EventTypeFRP)
	if len(byType) != 1 {
		t.Fatalf("按类型查询失败")
	}
}

func TestWhitelistCRUD(t *testing.T) {
	st := openTemp(t)
	id, err := st.CreateWhitelistEntry(&model.WhitelistEntry{Kind: "cidr", Value: "10.0.0.0/8", Note: "内网"})
	if err != nil {
		t.Fatalf("CreateWhitelistEntry: %v", err)
	}
	list, _ := st.ListWhitelist()
	if len(list) != 1 || list[0].Value != "10.0.0.0/8" {
		t.Fatalf("ListWhitelist: %+v", list)
	}
	if err := st.UpdateWhitelistEntry(&model.WhitelistEntry{ID: id, Kind: "cidr", Value: "172.16.0.0/12"}); err != nil {
		t.Fatalf("UpdateWhitelistEntry: %v", err)
	}
	if err := st.DeleteWhitelistEntry(id); err != nil {
		t.Fatalf("DeleteWhitelistEntry: %v", err)
	}
	list, _ = st.ListWhitelist()
	if len(list) != 0 {
		t.Fatal("删除失败")
	}
}

func TestDomainCRUDAndAuditAndConfig(t *testing.T) {
	st := openTemp(t)
	id, err := st.CreateDomain(&model.NetDomain{Name: "gov", CIDRs: []string{"10.1.0.0/16"}, Color: "#F87171"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	d, _ := st.GetDomain(id)
	if d.Name != "gov" || len(d.CIDRs) != 1 {
		t.Fatalf("GetDomain: %+v", d)
	}
	d.Color = "#4ADE80"
	if err := st.UpdateDomain(d); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}
	domains, _ := st.ListDomains()
	if len(domains) != 1 || domains[0].Color != "#4ADE80" {
		t.Fatalf("ListDomains: %+v", domains)
	}

	if _, err := st.AddAuditLog(&model.AuditLog{Actor: "admin", Action: "confirm", Target: "event:1"}); err != nil {
		t.Fatalf("AddAuditLog: %v", err)
	}
	logs, _ := st.ListAuditLogs(10)
	if len(logs) != 1 || logs[0].Actor != "admin" {
		t.Fatalf("ListAuditLogs: %+v", logs)
	}

	if err := st.SetConfigKV("aging_seconds", "3600"); err != nil {
		t.Fatalf("SetConfigKV: %v", err)
	}
	v, _ := st.GetConfigKV("aging_seconds")
	if v != "3600" {
		t.Fatalf("GetConfigKV = %q", v)
	}
	if err := st.SetConfigKV("aging_seconds", "7200"); err != nil {
		t.Fatalf("SetConfigKV update: %v", err)
	}
	v, _ = st.GetConfigKV("aging_seconds")
	if v != "7200" {
		t.Fatalf("更新后 GetConfigKV = %q", v)
	}
}
