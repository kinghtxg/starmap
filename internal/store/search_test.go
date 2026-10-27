package store

import (
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

// 列表模糊搜索（1.3.1 起前端改为真·服务端分页，筛选必须一起下沉到 SQL）。
//
// 为什么这些测试必须存在：如果筛选留在前端而分页搬到服务端，
// 用户在第 2 页看到的"筛选结果"只覆盖当前页的 50 条——
// 这不是"少显示几条"，而是给出**错误结论**（明明有匹配却说不存在）。
// 所以关键字过滤必须在 SQL 里，且列表与计数共用同一份条件。

func TestEventKeywordSearch(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	mk := func(title, detail string) {
		t.Helper()
		if _, err := st.CreateEvent(&model.RiskEvent{
			Type: "frp", NodeID: 1, Title: title, Detail: detail, Level: "mid",
			Status: model.EventStatusPending, CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateEvent: %v", err)
		}
	}
	mk("疑似 frp 内网穿透", "主机 10.1.1.5 访问外网 1.2.3.4:7000")
	mk("内网多网段主机", "节点同时出现在 10.1.1.0/24 与 10.2.2.0/24")
	mk("未知出站流量", "目标 8.8.8.8:443")

	cases := []struct {
		name string
		kw   string
		want int
	}{
		{"标题命中", "frp", 1},
		{"详情命中IP", "10.1.1.5", 1},
		{"中文命中", "多网段", 1},
		{"多行命中", "10.1.1", 2}, // 第 1 条详情 + 第 2 条详情
		{"空关键字=不筛选", "", 3},
		{"无匹配", "不存在的关键字", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := EventFilter{Keyword: c.kw}
			list, err := st.ListEventsPaged(f, 0, 0)
			if err != nil {
				t.Fatalf("ListEventsPaged: %v", err)
			}
			if len(list) != c.want {
				t.Fatalf("关键字 %q 命中 %d 条，期望 %d", c.kw, len(list), c.want)
			}
			// 计数必须与列表一致，否则前端"共 N 条"会撒谎
			n, err := st.CountEvents(f)
			if err != nil {
				t.Fatalf("CountEvents: %v", err)
			}
			if n != len(list) {
				t.Fatalf("关键字 %q 的计数 %d 与列表 %d 不一致", c.kw, n, len(list))
			}
		})
	}
}

func TestAssetKeywordSearch(t *testing.T) {
	st := openTest(t)
	mk := func(a model.Asset) {
		t.Helper()
		if _, err := st.UpsertAsset(&a); err != nil {
			t.Fatalf("UpsertAsset: %v", err)
		}
	}
	now := time.Now()
	mk(model.Asset{
		NodeKey: "ip:10.9.9.1", IPs: []string{"10.9.9.1"}, MAC: "aa:bb:cc:00:11:22",
		Hostname: "web-01", OS: "CentOS 7", Status: model.AssetArchived,
		Owner: "张三", Department: "信息中心", LastSeen: now,
	})
	mk(model.Asset{
		NodeKey: "ip:10.9.9.2", IPs: []string{"10.9.9.2"}, MAC: "aa:bb:cc:00:33:44",
		Hostname: "db-01", OS: "Ubuntu 22", Status: model.AssetUnarchived,
		Department: "财务部", LastSeen: now,
	})

	cases := []struct {
		name   string
		filter AssetFilter
		want   int
	}{
		{"按IP", AssetFilter{Keyword: "10.9.9.1"}, 1},
		{"按主机名", AssetFilter{Keyword: "web"}, 1},
		{"按归属人", AssetFilter{Keyword: "张三"}, 1},
		{"按部门", AssetFilter{Keyword: "财务"}, 1},
		{"按MAC片段", AssetFilter{Keyword: "00:11"}, 1},
		{"按OS", AssetFilter{Keyword: "centos"}, 1}, // LIKE 对 ASCII 大小写不敏感
		{"关键字+状态", AssetFilter{Keyword: "10.9.9", Status: model.AssetArchived}, 1},
		{"状态无交集", AssetFilter{Keyword: "web", Status: model.AssetUnarchived}, 0},
		{"空=全量", AssetFilter{}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			list, err := st.ListAssetsPaged(c.filter, 0, 0)
			if err != nil {
				t.Fatalf("ListAssetsPaged: %v", err)
			}
			if len(list) != c.want {
				t.Fatalf("%+v 命中 %d 条，期望 %d", c.filter, len(list), c.want)
			}
			n, err := st.CountAssets(c.filter)
			if err != nil {
				t.Fatalf("CountAssets: %v", err)
			}
			if n != len(list) {
				t.Fatalf("计数 %d 与列表 %d 不一致", n, len(list))
			}
		})
	}
}

func TestPortKeywordSearch(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	recs := []model.PortRecord{
		{NodeKey: "ip:10.5.5.1", IP: "10.5.5.1", Port: 80, Proto: "tcp", Service: "http",
			State: "open", Source: "discover", FirstSeen: now, LastSeen: now,
			Product: "nginx", Version: "1.24.0", Title: "Welcome to nginx"},
		{NodeKey: "ip:10.5.5.1", IP: "10.5.5.1", Port: 443, Proto: "tcp", Service: "https",
			State: "open", Source: "discover", FirstSeen: now, LastSeen: now,
			Product: "nginx", TLSCN: "oa.corp.example"},
	}
	for i := range recs {
		if err := st.UpsertPort(&recs[i]); err != nil {
			t.Fatalf("UpsertPort: %v", err)
		}
	}

	cases := []struct {
		name   string
		filter PortFilter
		want   int
	}{
		{"按服务名", PortFilter{Keyword: "https"}, 1},
		{"按产品", PortFilter{Keyword: "nginx"}, 2},
		{"按标题", PortFilter{Keyword: "Welcome"}, 1},
		{"按证书CN", PortFilter{Keyword: "oa.corp"}, 1},
		{"按IP片段", PortFilter{Keyword: "10.5.5"}, 2},
		{"IP+关键字", PortFilter{IP: "10.5.5.1", Keyword: "https"}, 1},
		{"空=全量", PortFilter{}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			list, err := st.ListPortsPaged(c.filter, 0, 0)
			if err != nil {
				t.Fatalf("ListPortsPaged: %v", err)
			}
			if len(list) != c.want {
				t.Fatalf("%+v 命中 %d 条，期望 %d", c.filter, len(list), c.want)
			}
			n, err := st.CountPorts(c.filter)
			if err != nil {
				t.Fatalf("CountPorts: %v", err)
			}
			if n != len(list) {
				t.Fatalf("计数 %d 与列表 %d 不一致", n, len(list))
			}
		})
	}
}

// TestKeywordLikeEscaping 通配符必须被转义。
//
// 不转义时用户搜 "%" 会命中全部记录（等于搜索失灵），搜 "_" 会变成单字符通配。
// 这类 bug 不会报错，只会让人怀疑"搜索是不是坏的"。
func TestKeywordLikeEscaping(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	for _, title := range []string{"折扣 100% 完成", "普通告警 A", "普通告警 B"} {
		if _, err := st.CreateEvent(&model.RiskEvent{
			Type: "frp", NodeID: 1, Title: title, Level: "mid",
			Status: model.EventStatusPending, CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateEvent: %v", err)
		}
	}

	// 搜字面量 "%" 只应命中含百分号的那条，而不是全部 3 条
	list, err := st.ListEventsPaged(EventFilter{Keyword: "%"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("搜 %%%% 应只命中 1 条，实际 %d 条（%% 被当成通配符）", len(list))
	}
	if !strings.Contains(list[0].Title, "100%") {
		t.Fatalf("命中的不是含百分号的记录：%q", list[0].Title)
	}

	// 搜字面量 "_" 同理：没有记录含下划线，应为 0 条
	if got, err := st.ListEventsPaged(EventFilter{Keyword: "_"}, 0, 0); err != nil || len(got) != 0 {
		t.Fatalf("搜下划线应命中 0 条，实际 %d 条 err=%v", len(got), err)
	}
}

// TestKeywordSearchPaging 搜索 + 分页组合：翻页不能重复或漏行。
func TestKeywordSearchPaging(t *testing.T) {
	st := openTest(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		if _, err := st.CreateEvent(&model.RiskEvent{
			Type: "frp", NodeID: 1, Title: "frp 穿透告警", Level: "mid",
			Status: model.EventStatusPending, CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("CreateEvent: %v", err)
		}
	}
	// 混入 5 条不匹配的，确保筛选真的在 SQL 里生效
	for i := 0; i < 5; i++ {
		if _, err := st.CreateEvent(&model.RiskEvent{
			Type: "clash", NodeID: 1, Title: "其他告警", Level: "low",
			Status: model.EventStatusPending, CreatedAt: base,
		}); err != nil {
			t.Fatalf("CreateEvent: %v", err)
		}
	}

	f := EventFilter{Keyword: "frp"}
	seen := map[int64]bool{}
	for off := 0; off < 10; off += 3 {
		page, err := st.ListEventsPaged(f, 3, off)
		if err != nil {
			t.Fatalf("offset=%d: %v", off, err)
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("事件 %d 跨页重复出现（offset=%d）", e.ID, off)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 10 {
		t.Fatalf("翻完应看到全部 10 条匹配记录，实际 %d 条", len(seen))
	}
}
