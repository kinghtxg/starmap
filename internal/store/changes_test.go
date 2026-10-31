package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func newChangeStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/changes.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func putPort(t *testing.T, st *Store, ip string, port int, first, last time.Time) {
	t.Helper()
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:" + ip, IP: ip, Port: port, Proto: "tcp",
		Service: "http", State: "open", Source: "probe",
		FirstSeen: first, LastSeen: last,
	}); err != nil {
		t.Fatalf("写端口 %s:%d 失败: %v", ip, port, err)
	}
}

// TestPortChangesWindowSemantics 变更窗口的语义边界。
//
// 这是变更页唯一有争议的地方，用四种组合把它钉死：
//   - 窗口前就在、现在还在      → 两边都不出现（没变）
//   - 窗口内首次出现、仍然活着  → added
//   - 窗口前就在、窗口内不再活动 → gone
//   - 窗口内刚出现就不再活动    → 只算 added（first_seen 落在窗口内）
//
// 最后一条正是 added/gone 必须用 first_seen<since 互斥的原因：
// 否则一条"刚上线就挂了"的记录会同时出现在两栏里，
// 用户看到的是"新增 1，消失 1"，而实际只是同一条线掉下去了。
func TestPortChangesWindowSemantics(t *testing.T) {
	st := newChangeStore(t)
	now := time.Now()
	since := now.AddDate(0, 0, -7)

	putPort(t, st, "10.0.0.1", 80, now.AddDate(0, 0, -30), now.Add(-time.Hour))      // 一直在
	putPort(t, st, "10.0.0.2", 443, now.AddDate(0, 0, -2), now.Add(-time.Minute))    // 窗口内新增
	putPort(t, st, "10.0.0.3", 3389, now.AddDate(0, 0, -30), now.AddDate(0, 0, -10)) // 窗口内不再活动
	putPort(t, st, "10.0.0.4", 8080, now.AddDate(0, 0, -2), now.AddDate(0, 0, -2))   // 新增后又掉线

	added, gone, addedTotal, goneTotal, err := st.PortChanges(
		ChangeWindow{Since: since, Until: now.Add(time.Minute)}, 100)
	if err != nil {
		t.Fatalf("查询变更失败: %v", err)
	}

	if addedTotal != 2 {
		t.Fatalf("新增计数应为 2（10.0.0.2 / 10.0.0.4），实际 %d", addedTotal)
	}
	if goneTotal != 1 {
		t.Fatalf("消失计数应为 1（10.0.0.3），实际 %d", goneTotal)
	}

	addedSet := map[string]bool{}
	for _, p := range added {
		addedSet[p.IP] = true
	}
	if !addedSet["10.0.0.2"] || !addedSet["10.0.0.4"] {
		t.Fatalf("新增集合不符: %#v", addedSet)
	}
	if addedSet["10.0.0.1"] {
		t.Fatal("一直在线的端口不该算新增")
	}

	for _, p := range gone {
		if p.IP != "10.0.0.3" {
			t.Fatalf("消失集合混入了 %s:%d", p.IP, p.Port)
		}
		if p.Port != 3389 {
			t.Fatalf("消失记录端口不符: %d", p.Port)
		}
	}
}

// TestPortChangesRespectsLimit 结果集受 limit 限制，但 total 仍是全量。
func TestPortChangesRespectsLimit(t *testing.T) {
	st := newChangeStore(t)
	now := time.Now()
	for i := 1; i <= 5; i++ {
		ip := "10.0.1." + string(rune('0'+i))
		putPort(t, st, ip, 80, now.Add(-time.Hour), now)
	}
	added, _, total, _, err := st.PortChanges(
		ChangeWindow{Since: now.AddDate(0, 0, -1), Until: now.Add(time.Minute)}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("limit 未生效: %d", len(added))
	}
	if total != 5 {
		t.Fatalf("total 应是全量 5，实际 %d——被 limit 截断会让界面误报「共 2 条」", total)
	}
}

// TestTrendStatsAlignment 趋势序列长度恒等于 days，缺失的天补 0，最后一天是今天。
//
// 前端折线图按数组下标画 X 轴：缺一天会把后面所有点左移一格。
func TestTrendStatsAlignment(t *testing.T) {
	st := newChangeStore(t)
	now := time.Date(2026, 5, 20, 14, 30, 0, 0, time.Local)

	// 今天两条端口、昨天一条、10 天前一条（应被 days=7 排除）
	putPort(t, st, "10.0.0.1", 80, now.Add(-time.Hour), now)
	putPort(t, st, "10.0.0.2", 81, now.Add(-2*time.Hour), now)
	putPort(t, st, "10.0.0.3", 82, now.AddDate(0, 0, -1), now.AddDate(0, 0, -1))
	putPort(t, st, "10.0.0.4", 83, now.AddDate(0, 0, -10), now.AddDate(0, 0, -10))

	points, err := st.TrendStats(7, now)
	if err != nil {
		t.Fatalf("趋势查询失败: %v", err)
	}
	if len(points) != 7 {
		t.Fatalf("序列长度应为 7，实际 %d", len(points))
	}
	if points[6].Date != "2026-05-20" {
		t.Fatalf("最后一天应是今天，实际 %q", points[6].Date)
	}
	if points[0].Date != "2026-05-14" {
		t.Fatalf("第一天应是 7 天前的 05-14，实际 %q", points[0].Date)
	}
	// 日期必须连续
	for i := 1; i < len(points); i++ {
		prev, _ := time.Parse("2006-01-02", points[i-1].Date)
		cur, _ := time.Parse("2006-01-02", points[i].Date)
		if cur.Sub(prev) != 24*time.Hour {
			t.Fatalf("日期不连续: %s → %s", points[i-1].Date, points[i].Date)
		}
	}
	if points[6].Ports != 2 {
		t.Fatalf("今天的端口数应为 2，实际 %d", points[6].Ports)
	}
	if points[5].Ports != 1 {
		t.Fatalf("昨天的端口数应为 1，实际 %d", points[5].Ports)
	}
	if points[0].Ports != 0 {
		t.Fatalf("无数据的天应补 0，实际 %d", points[0].Ports)
	}
}

// TestTrendStatsClampsDays 非法/超范围 days 被夹取，不会退化成"查全表"。
func TestTrendStatsClampsDays(t *testing.T) {
	st := newChangeStore(t)
	now := time.Now()
	for _, d := range []int{0, -3, 1000} {
		points, err := st.TrendStats(d, now)
		if err != nil {
			t.Fatalf("days=%d 失败: %v", d, err)
		}
		if len(points) < 1 || len(points) > 90 {
			t.Fatalf("days=%d 未被夹取，得到 %d 个点", d, len(points))
		}
	}
}

// TestSortChangesByIP 按 IP 数值序，而不是字符串序。
func TestSortChangesByIP(t *testing.T) {
	list := []model.PortRecord{
		{IP: "10.0.0.10", Port: 80},
		{IP: "10.0.0.2", Port: 80},
		{IP: "10.0.0.2", Port: 22},
		{IP: "9.0.0.1", Port: 80},
	}
	SortChangesByIP(list)
	want := []struct {
		ip   string
		port int
	}{{"9.0.0.1", 80}, {"10.0.0.2", 22}, {"10.0.0.2", 80}, {"10.0.0.10", 80}}
	for i, w := range want {
		if list[i].IP != w.ip || list[i].Port != w.port {
			t.Fatalf("第 %d 项应为 %s:%d，实际 %s:%d", i, w.ip, w.port, list[i].IP, list[i].Port)
		}
	}
}
