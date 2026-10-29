package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// 本地情报库的核心语义是"覆盖"：同一条指标重复推送必须以最新版本为准，
// 且旧版本不能把新版本洗回去。这几个用例就是这条语义的护栏。

func newIntelStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func rec(ind, verdict string, ver int64, at time.Time) model.IntelRecord {
	return model.IntelRecord{
		Indicator: ind, Verdict: verdict, Version: ver, UpdatedAt: at,
		Score: 90, Tags: []string{"c2"}, Source: "ti",
	}
}

func TestIntelUpsertOverwritesWithLatest(t *testing.T) {
	st := newIntelStore(t)
	t1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	stat, err := st.UpsertIntelBatch([]model.IntelRecord{rec("1.2.3.4", "malicious", 1, t1)})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Inserted != 1 {
		t.Fatalf("首推应新增 1 条，实际 %+v", stat)
	}

	// 同一条记录、更高版本、不同结论 → 必须覆盖
	stat, err = st.UpsertIntelBatch([]model.IntelRecord{
		rec("1.2.3.4", "clean", 2, t1.Add(time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Updated != 1 {
		t.Fatalf("重复推送应覆盖 1 条，实际 %+v", stat)
	}
	got, _ := st.LookupIntel("1.2.3.4")
	if got == nil || got.Verdict != "clean" || got.Version != 2 {
		t.Fatalf("覆盖失败，库里是 %+v", got)
	}

	// 库里只剩一条（不是追加）
	stats, _ := st.IntelStats()
	if stats["total"].(int) != 1 {
		t.Fatalf("同一指标应只占一行，实际 %v 行", stats["total"])
	}
}

func TestIntelRejectsStaleAndCountsUnchanged(t *testing.T) {
	st := newIntelStore(t)
	t2 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	if _, err := st.UpsertIntelBatch([]model.IntelRecord{rec("8.8.8.8", "malicious", 5, t2)}); err != nil {
		t.Fatal(err)
	}

	// 完全相同的重发 → unchanged，不写库
	stat, err := st.UpsertIntelBatch([]model.IntelRecord{rec("8.8.8.8", "malicious", 5, t2)})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Unchanged != 1 || stat.Updated != 0 || stat.Inserted != 0 {
		t.Fatalf("同版本重发应记为 unchanged，实际 %+v", stat)
	}

	// 迟到的旧包（版本更低）→ stale，且绝不覆盖
	stat, err = st.UpsertIntelBatch([]model.IntelRecord{rec("8.8.8.8", "clean", 4, t2.Add(-time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Stale != 1 || stat.Updated != 0 {
		t.Fatalf("旧版本应被拒，实际 %+v", stat)
	}
	got, _ := st.LookupIntel("8.8.8.8")
	if got.Verdict != "malicious" || got.Version != 5 {
		t.Fatalf("旧包把新结论洗回去了：%+v", got)
	}
}

// 同一个 (version, updated_at) 声称两种结论：拒绝，且必须与"版本旧"区分开。
//
// 为什么不能放行：先推 malicious 再推 clean（版本号不变），等于允许在不留痕的情况下
// 改写已发布的判定——事后从库里看不出哪一次是对的。也不能混进 stale：
// 那个计数会让推送方去查时钟，而问题其实在版本号没升。
func TestIntelSameVersionConflictRejected(t *testing.T) {
	st := newIntelStore(t)
	t2 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	if _, err := st.UpsertIntelBatch([]model.IntelRecord{rec("9.9.9.9", "malicious", 7, t2)}); err != nil {
		t.Fatal(err)
	}

	// 同版本、同时间、不同结论 → conflict，不覆盖
	stat, err := st.UpsertIntelBatch([]model.IntelRecord{rec("9.9.9.9", "clean", 7, t2)})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Conflict != 1 || stat.Stale != 0 || stat.Updated != 0 || stat.Unchanged != 0 {
		t.Fatalf("同版本不同结论应记为 conflict 且不写库，实际 %+v", stat)
	}
	got, _ := st.LookupIntel("9.9.9.9")
	if got.Verdict != "malicious" {
		t.Fatalf("同版本冲突把结论改了：%+v", got)
	}

	// 升版本后必须能改（否则情报永远纠正不了）
	stat, err = st.UpsertIntelBatch([]model.IntelRecord{rec("9.9.9.9", "clean", 8, t2)})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Updated != 1 {
		t.Fatalf("升版本应覆盖，实际 %+v", stat)
	}
	if got, _ := st.LookupIntel("9.9.9.9"); got.Verdict != "clean" || got.Version != 8 {
		t.Fatalf("升版本后结论未更新：%+v", got)
	}
}

func TestIntelNormalization(t *testing.T) {
	cases := []struct{ in, want, kind string }{
		{"1.2.3.4", "1.2.3.4", "ip"},
		{" 1.2.3.4 ", "1.2.3.4", "ip"},
		{"1.2.3.4/32", "1.2.3.4", "ip"},
		{"\"1.2.3.4\"", "1.2.3.4", "ip"},
		{"1.2.3.0/24", "1.2.3.0/24", "cidr"},
		{"2001:DB8::1", "2001:db8::1", "ip"},
		{"Evil.COM", "evil.com", "domain"},
	}
	for _, c := range cases {
		got, kind, ok := NormalizeIndicator(c.in)
		if !ok || got != c.want || kind != c.kind {
			t.Errorf("NormalizeIndicator(%q) = (%q,%q,%v)，期望 (%q,%q,true)",
				c.in, got, kind, ok, c.want, c.kind)
		}
	}
	for _, bad := range []string{"", "   ", "1.2.3", "1.2.3.4/33", "not an ip!", "a b c"} {
		if got, _, ok := NormalizeIndicator(bad); ok {
			t.Errorf("NormalizeIndicator(%q) 应判非法，实际 (%q, ok)", bad, got)
		}
	}
}

func TestIntelInvalidDoesNotAbortBatch(t *testing.T) {
	st := newIntelStore(t)
	now := time.Now().UTC()
	stat, err := st.UpsertIntelBatch([]model.IntelRecord{
		rec("1.1.1.1", "malicious", 1, now),
		{Indicator: "这不是IP", Verdict: "malicious"},
		rec("9.9.9.9", "suspicious", 1, now),
	})
	if err != nil {
		t.Fatalf("单条脏数据不该让整批失败: %v", err)
	}
	if stat.Invalid != 1 || stat.Inserted != 2 {
		t.Fatalf("应为 1 条非法 + 2 条入库，实际 %+v", stat)
	}
}

func TestIntelSameBatchDedupKeepsNewest(t *testing.T) {
	st := newIntelStore(t)
	now := time.Now().UTC()
	// 同一批里同一个 IP 出现两次：按版本取新的，且只入库一条
	stat, err := st.UpsertIntelBatch([]model.IntelRecord{
		rec("2.2.2.2", "malicious", 1, now),
		rec("2.2.2.2", "clean", 3, now.Add(time.Minute)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stat.Inserted != 1 {
		t.Fatalf("批内重复应合并为 1 条，实际 %+v", stat)
	}
	got, _ := st.LookupIntel("2.2.2.2")
	if got.Verdict != "clean" || got.Version != 3 {
		t.Fatalf("批内应取最新版本，实际 %+v", got)
	}
}

func TestIntelBatchLookupAndPrune(t *testing.T) {
	st := newIntelStore(t)
	old := time.Now().UTC().AddDate(0, 0, -200)
	fresh := time.Now().UTC()
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{
		rec("3.3.3.3", "malicious", 1, old),
		rec("4.4.4.4", "malicious", 1, fresh),
		rec("10.1.1.5", "suspicious", 1, fresh), // 内网 IOC 也要能存能查
	}); err != nil {
		t.Fatal(err)
	}

	m, err := st.LookupIntelBatch([]string{"3.3.3.3", "4.4.4.4", "5.5.5.5", "10.1.1.5", "bad"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("应命中 3 条，实际 %d", len(m))
	}
	if m["10.1.1.5"].Verdict != "suspicious" {
		t.Fatal("内网地址的本地情报必须能查到（本地查询不外发，不受公网限制）")
	}

	n, err := st.PruneIntel(90)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应清掉 1 条过期情报，实际 %d", n)
	}
	if _, ok := m["3.3.3.3"]; !ok {
		t.Fatal("前置查询应命中")
	}
	if got, _ := st.LookupIntel("3.3.3.3"); got != nil {
		t.Fatal("超过保留期的情报应被清理")
	}
	// 0 = 不清理
	if n, _ := st.PruneIntel(0); n != 0 {
		t.Fatal("保留期 0 表示不清理")
	}
}

func TestIntelRemoteRecordExpiry(t *testing.T) {
	st := newIntelStore(t)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	r := rec("6.6.6.6", "clean", 0, now)
	r.Source = "remote"
	r.ExpiresAt = &exp
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{r}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.LookupIntel("6.6.6.6")
	if got == nil || got.ExpiresAt == nil {
		t.Fatal("回源记录应带有效期，否则查过一次 clean 就永远不再问")
	}
	if !got.ExpiresAt.After(now) {
		t.Fatalf("有效期应当在未来，实际 %v", got.ExpiresAt)
	}
}

// TestIntelStatsHasTimestamps：统计里的时间字段必须是真实值，不能是 nil。
//
// 这条曾经踩过：MAX(received_at) 是聚合表达式，驱动拿不到列类型，
// 扫进 time.Time 静默失败，界面上"最后入库"永远是 "-"，
// 看起来像"情报从没更新过"，而不是像"代码有 bug"。
func TestIntelStatsHasTimestamps(t *testing.T) {
	st := newIntelStore(t)
	old := time.Now().UTC().AddDate(0, 0, -3)
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{
		rec("7.7.7.7", "malicious", 1, old),
	}); err != nil {
		t.Fatal(err)
	}
	stats, err := st.IntelStats()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"last_received_at", "oldest_updated_at"} {
		v, ok := stats[k].(string)
		if !ok || v == "" {
			t.Fatalf("%s 应有值，实际 %v", k, stats[k])
		}
		if _, perr := time.Parse(time.RFC3339, v); perr != nil {
			t.Fatalf("%s 不是 RFC3339：%q", k, v)
		}
	}
}
