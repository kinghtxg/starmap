package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// 列表分页与保留期清理。
//
// 这两件事都属于"平时看不出来、出事就是事故"的类型：
// 分页写错会让调用方少看到数据却毫无察觉；保留期不清理会让库文件无限增长直到磁盘满。

func mkEvent(t *testing.T, st *Store, typ, status string, at time.Time) {
	t.Helper()
	if _, err := st.CreateEvent(&model.RiskEvent{
		Type: typ, NodeID: 1, Title: "t", Level: "mid",
		Status: status, CreatedAt: at,
	}); err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
}

func TestEventsPaging(t *testing.T) {
	st := openTest(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		mkEvent(t, st, "frp", model.EventStatusPending, base.Add(time.Duration(i)*time.Minute))
	}

	all, err := st.ListEvents("", "")
	if err != nil || len(all) != 10 {
		t.Fatalf("全量查询应有 10 条，实际 %d err=%v", len(all), err)
	}

	page, err := st.ListEventsPaged("", "", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 3 {
		t.Fatalf("limit=3 应返回 3 条，实际 %d", len(page))
	}
	// 排序是 id DESC：第一页应是最近插入的 3 条
	if page[0].ID <= page[2].ID {
		t.Errorf("应按 id 倒序，实际首尾 %d / %d", page[0].ID, page[2].ID)
	}

	// 翻页不能重复也不能漏
	seen := map[int64]bool{}
	for off := 0; off < 10; off += 3 {
		p, err := st.ListEventsPaged("", "", 3, off)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p {
			if seen[e.ID] {
				t.Fatalf("事件 %d 在分页中重复出现", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 10 {
		t.Errorf("遍历全部分页应覆盖 10 条，实际 %d", len(seen))
	}

	// 只给 offset 不给 limit：SQLite 需要 LIMIT -1 才能用 OFFSET
	p, err := st.ListEventsPaged("", "", 0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 2 {
		t.Errorf("offset=8 应剩 2 条，实际 %d", len(p))
	}

	if n, err := st.CountEvents("", ""); err != nil || n != 10 {
		t.Errorf("CountEvents = %d err=%v，期望 10", n, err)
	}
	if n, err := st.CountEvents(model.EventStatusConfirmed, ""); err != nil || n != 0 {
		t.Errorf("按状态计数应为 0，实际 %d err=%v", n, err)
	}
}

func TestAssetsPagingAndCount(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	for i := 0; i < 7; i++ {
		if _, err := st.UpsertAsset(&model.Asset{
			NodeKey: "mac:aa:bb:cc:dd:ee:0" + string(rune('0'+i)),
			IPs:     []string{"10.0.0." + string(rune('0'+i))},
			Status:  model.AssetUnarchived, FirstSeen: now, LastSeen: now,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListAssetsPaged("", 4, 0)
	if err != nil || len(page) != 4 {
		t.Fatalf("limit=4 应返回 4 条，实际 %d err=%v", len(page), err)
	}
	if n, err := st.CountAssets(""); err != nil || n != 7 {
		t.Errorf("CountAssets = %d err=%v，期望 7", n, err)
	}
}

func TestPortsPagingAndCount(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	for i := 0; i < 20; i++ {
		if err := st.UpsertPort(&model.PortRecord{
			NodeKey: "mac:x", IP: "10.0.0.1", Port: 1000 + i, Proto: "tcp",
			State: "open", Source: "probe", FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListPortsPaged("10.0.0.1", "", 5, 0)
	if err != nil || len(page) != 5 {
		t.Fatalf("limit=5 应返回 5 条，实际 %d err=%v", len(page), err)
	}
	// 排序含 id，翻页不该出现同一行跨页重复
	seen := map[int64]bool{}
	for off := 0; off < 20; off += 5 {
		p, err := st.ListPortsPaged("10.0.0.1", "", 5, off)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p {
			if seen[r.ID] {
				t.Fatalf("端口记录 %d 跨页重复", r.ID)
			}
			seen[r.ID] = true
		}
	}
	if n, err := st.CountPorts("10.0.0.1", ""); err != nil || n != 20 {
		t.Errorf("CountPorts = %d err=%v，期望 20", n, err)
	}
	if n, err := st.CountPorts("10.0.0.1", "mac:none"); err != nil || n != 0 {
		t.Errorf("按 node_key 过滤应命中 0 条，实际 %d", n)
	}
}

func TestDeleteEventsBeforeKeepsPending(t *testing.T) {
	st := openTest(t)
	old := time.Now().AddDate(0, 0, -30)
	mkEvent(t, st, "frp", model.EventStatusPending, old)        // 过期但未处置
	mkEvent(t, st, "frp", model.EventStatusConfirmed, old)      // 过期已处置
	mkEvent(t, st, "clash", model.EventStatusDeferred, old)     // 过期已处置
	mkEvent(t, st, "frp", model.EventStatusPending, time.Now()) // 未过期

	cutoff := time.Now().AddDate(0, 0, -7)
	n, err := st.DeleteEventsBefore(cutoff, true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("应只删除 2 条已处置的过期事件，实际 %d", n)
	}
	left, _ := st.ListEvents("", "")
	if len(left) != 2 {
		t.Fatalf("应剩 2 条（1 条过期未处置 + 1 条未过期），实际 %d", len(left))
	}
	for _, e := range left {
		if e.Status != model.EventStatusPending {
			t.Errorf("保留下来的都应是待处置事件，实际 %s", e.Status)
		}
	}

	// onlyResolved=false 时连未处置一起清（运维手动深度清理的口子）
	if n, err := st.DeleteEventsBefore(cutoff, false); err != nil || n != 1 {
		t.Errorf("清全部过期事件应删 1 条，实际 %d err=%v", n, err)
	}
}

func TestDeleteAuditLogsBefore(t *testing.T) {
	st := openTest(t)
	old := time.Now().AddDate(0, 0, -100)
	if _, err := st.AddAuditLog(&model.AuditLog{
		Actor: "admin", Action: "config_update", Target: "system", CreatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAuditLog(&model.AuditLog{
		Actor: "admin", Action: "config_update", Target: "system", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := st.DeleteAuditLogsBefore(time.Now().AddDate(0, 0, -90))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("应删除 1 条超过保留期的审计日志，实际 %d", n)
	}
	logs, _ := st.ListAuditLogs(10)
	if len(logs) != 1 {
		t.Errorf("应剩 1 条，实际 %d", len(logs))
	}
}
