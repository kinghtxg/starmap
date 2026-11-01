package store

// 站点总数缓存的语义测试。
//
// 缓存最容易出的不是"没命中"，而是"该失效时没失效"——用户看到的总数
// 和列表条数对不上，然后没人能解释为什么。所以这里的重点是失效点，
// 不是命中率。

import (
	"strconv"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestSiteCountCacheInvalidatesOnWrite 任何一条改 ports 的写路径都必须让总数立刻更新。
func TestSiteCountCacheInvalidatesOnWrite(t *testing.T) {
	st, err := Open(t.TempDir() + "/countcache.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	seedSite(t, st, "10.70.0.1", 80, nil)
	n, err := st.CountSites(SiteFilter{})
	if err != nil {
		t.Fatalf("查总数失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("总数 = %d，期望 1", n)
	}

	// 1) 单条 upsert
	seedSite(t, st, "10.70.0.2", 80, nil)
	if n, _ := st.CountSites(SiteFilter{}); n != 2 {
		t.Fatalf("单条写入后总数 = %d，期望 2（缓存没失效）", n)
	}

	// 2) 批量 upsert
	batch := []model.PortRecord{
		{NodeKey: "ip:10.70.0.3", IP: "10.70.0.3", Port: 80, Proto: "tcp", State: "open",
			HTTPStatus: 200, Title: "A", FirstSeen: time.Now(), LastSeen: time.Now()},
		{NodeKey: "ip:10.70.0.4", IP: "10.70.0.4", Port: 80, Proto: "tcp", State: "open",
			HTTPStatus: 200, Title: "B", FirstSeen: time.Now(), LastSeen: time.Now()},
	}
	if err := st.UpsertPorts(batch); err != nil {
		t.Fatalf("批量写入失败: %v", err)
	}
	if n, _ := st.CountSites(SiteFilter{}); n != 4 {
		t.Fatalf("批量写入后总数 = %d，期望 4（缓存没失效）", n)
	}

	// 3) 标记 stale —— 站点判据要求 state='open'，变成 stale 就不再是站点
	if _, err := st.MarkStalePorts(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("标记 stale 失败: %v", err)
	}
	if n, _ := st.CountSites(SiteFilter{}); n != 0 {
		t.Fatalf("全部标记 stale 后总数 = %d，期望 0（缓存没失效）", n)
	}

	// 4) 按 node_key 删除
	seedSite(t, st, "10.70.0.9", 80, nil)
	if n, _ := st.CountSites(SiteFilter{}); n != 1 {
		t.Fatalf("重新写入后总数 = %d，期望 1", n)
	}
	if _, err := st.DeletePortsByKey("ip:10.70.0.9"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n, _ := st.CountSites(SiteFilter{}); n != 0 {
		t.Fatalf("删除后总数 = %d，期望 0（缓存没失效）", n)
	}
}

// TestSiteCountCacheSkipsWhenFiltered 带筛选条件时不走缓存，结果必须与列表一致。
//
// 如果筛选也命中同一个缓存，用户换个筛选条件就会看到"总数没变但列表变了"。
func TestSiteCountCacheSkipsWhenFiltered(t *testing.T) {
	st, err := Open(t.TempDir() + "/countfilter.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	seedSite(t, st, "10.71.0.1", 80, nil) // http
	seedSite(t, st, "10.71.0.2", 443, func(p *model.PortRecord) {
		p.TLSCN, p.CertIssuer = "a.local", "CA"
		p.CertExpiry = now.AddDate(0, 0, 10).Format("2006-01-02")
	})
	seedSite(t, st, "10.71.0.3", 8443, func(p *model.PortRecord) {
		p.TLSCN, p.CertIssuer = "b.local", "CA"
		p.CertExpiry = now.AddDate(0, 0, -3).Format("2006-01-02")
	})

	// 先查一次无筛选，把缓存填上
	if n, _ := st.CountSites(SiteFilter{}); n != 3 {
		t.Fatalf("总数 = %d，期望 3", n)
	}

	cases := []struct {
		name string
		f    SiteFilter
		want int
	}{
		{"https", SiteFilter{Scheme: "https"}, 2},
		{"expiring", SiteFilter{OnlyExpiring: true}, 1},
		{"expired", SiteFilter{OnlyExpired: true}, 1},
		{"port 80", SiteFilter{Port: 80}, 1},
		{"self_signed 无", SiteFilter{OnlySelfSigned: true}, 0},
	}
	for _, c := range cases {
		got, err := st.CountSites(c.f)
		if err != nil {
			t.Fatalf("%s 查总数失败: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s 总数 = %d，期望 %d（筛选条件可能命中了无筛选的缓存）", c.name, got, c.want)
		}
		// 同一条件查两次必须一致（这次才是缓存/非缓存的一致性）
		again, _ := st.CountSites(c.f)
		if again != got {
			t.Errorf("%s 两次结果不同: %d vs %d", c.name, got, again)
		}
	}
}

// TestSiteCountCacheConsistentWithList 总数必须等于不翻页时的列表长度。
//
// 这条是"缓存没写坏"的最终判据：用户看到"共 N 个"就该能翻到 N 条。
func TestSiteCountCacheConsistentWithList(t *testing.T) {
	st, err := Open(t.TempDir() + "/countlist.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	for i := 0; i < 25; i++ {
		seedSite(t, st, "10.72.1."+strconv.Itoa(i), 80, nil)
	}

	n, err := st.CountSites(SiteFilter{})
	if err != nil {
		t.Fatalf("查总数失败: %v", err)
	}
	sites, err := st.ListSites(SiteFilter{}, 0, 0)
	if err != nil {
		t.Fatalf("查列表失败: %v", err)
	}
	if n != len(sites) {
		t.Fatalf("总数 %d 与列表长度 %d 不一致", n, len(sites))
	}

	// 分页取回全部，条数也要对上
	var paged int
	for offset := 0; ; offset += 10 {
		page, err := st.ListSites(SiteFilter{}, 10, offset)
		if err != nil {
			t.Fatalf("分页失败: %v", err)
		}
		paged += len(page)
		if len(page) < 10 {
			break
		}
	}
	if paged != n {
		t.Fatalf("分页累计 %d 条，与总数 %d 不一致", paged, n)
	}
}
