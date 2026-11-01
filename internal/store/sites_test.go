package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// seedPort 写一条端口记录。
func seedPort(t *testing.T, st *Store, f func(*model.PortRecord)) {
	t.Helper()
	now := time.Now()
	p := model.PortRecord{
		NodeKey: "ip:10.0.0.1", IP: "10.0.0.1", Port: 80, Proto: "tcp",
		Service: "http", State: "open", Source: model.PortSourceProbe,
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}
	if f != nil {
		f(&p)
	}
	if err := st.UpsertPort(&p); err != nil {
		t.Fatalf("写端口失败: %v", err)
	}
}

// TestSitesDerivedFromPorts 站点判据：有 HTTP/S 应用层响应的 open 端口才算站点。
//
// 这条用例守的是"站点不是端口列表换个名字"：SSH banner、关闭的端口、纯流量端口
// 都不该出现在站点页——它们没有"业务系统"这层含义，混进来会把站点页变成第二个端口页。
func TestSitesDerivedFromPorts(t *testing.T) {
	st, err := Open(t.TempDir() + "/sites.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 1. 普通 Web：有状态码与标题 → 站点（http）
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.Title, p.Server, p.HTTPStatus = 80, "综合办公平台", "nginx", 200
		p.Product, p.Version = "nginx", "1.24"
	})
	// 2. HTTPS 站点：有状态码 + 证书（证书是附加情报，不是判据）→ 站点（https）
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.TLSCN, p.TLSNames = 443, "oa.corp.local", []string{"oa.corp.local", "10.0.0.1"}
		p.HTTPStatus = 200
		p.CertIssuer, p.CertExpiry, p.SelfSigned = "Corp-CA", time.Now().AddDate(0, 0, 10).Format("2006-01-02"), true
	})
	// 2b. 只有证书、没有 HTTP 响应 → **不是**站点。
	// 这是真机实测出来的：RDP（3389）会完成 TLS 握手并带回 CN=机器名 的自签证书，
	// 按"有证书"判定的话每台 Windows 机器都会多出一个 https 站点。
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.TLSCN, p.CertIssuer = 3389, "kinght", "kinght"
		p.CertExpiry, p.SelfSigned = time.Now().AddDate(0, 0, 142).Format("2006-01-02"), true
	})
	// 3. 非 Web：SSH banner → 不是站点
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.Service, p.Banner = 22, "ssh", "SSH-2.0-OpenSSH_8.0"
	})
	// 4. 关闭的端口 → 不是站点
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.State, p.Title, p.HTTPStatus = 8081, "closed", "旧的测试站", 200
	})

	sites, err := st.ListSites(SiteFilter{}, 0, 0)
	if err != nil {
		t.Fatalf("查站点失败: %v", err)
	}
	if len(sites) != 2 {
		for _, s := range sites {
			t.Logf("  站点: %s %q", s.Key, s.Title)
		}
		t.Fatalf("应有 2 个站点（80 + 443），实际 %d 个", len(sites))
	}

	byPort := map[int]model.Site{}
	for _, s := range sites {
		byPort[s.Port] = s
	}
	web, ok := byPort[80]
	if !ok {
		t.Fatal("80 端口没被识别成站点")
	}
	if web.Key != "http://10.0.0.1:80" {
		t.Fatalf("站点标识不对: %q（期望 http://10.0.0.1:80）", web.Key)
	}
	if web.Title != "综合办公平台" || web.Status != 200 || web.Server != "nginx" {
		t.Fatalf("站点字段没带出来: %+v", web)
	}

	tls, ok := byPort[443]
	if !ok {
		t.Fatal("443 端口没被识别成站点")
	}
	if tls.Key != "https://10.0.0.1:443" {
		t.Fatalf("TLS 站点标识不对: %q（期望 https://…）", tls.Key)
	}
	if !tls.SelfSigned || tls.CertIssuer != "Corp-CA" {
		t.Fatalf("证书情报没带出来: %+v", tls)
	}
	if tls.CertDaysLeft < 0 || tls.CertDaysLeft > 11 {
		t.Fatalf("证书剩余天数不对: %d（期望约 10）", tls.CertDaysLeft)
	}
	if len(tls.TLSNames) != 2 {
		t.Fatalf("证书 SAN 没解析出来: %v", tls.TLSNames)
	}
	// 风险标签：自签 + 30 天内到期，两个都该有
	assertRisk(t, tls, "self_signed")
	assertRisk(t, tls, "cert_expiring")
}

func assertRisk(t *testing.T, s model.Site, want string) {
	t.Helper()
	for _, r := range s.Risk {
		if r == want {
			return
		}
	}
	t.Fatalf("站点 %s 的风险标签缺少 %q（实际 %v）", s.Key, want, s.Risk)
}

// TestSitesDedupeByIPPort 同一 ip:port 的多行只能产出一个站点，取 last_seen 最新的那行。
//
// 真实成因：同一台机器既被流量看到（node_key 由 MAC 推导），又被扫描器写入
// （node_key 由 IP 推导），唯一键是 (node_key,ip,port,proto)，于是两行并存。
// 不去重的话站点页会出现两个一模一样的"http://10.0.0.9:80"，其中一个还是过期的。
func TestSitesDedupeByIPPort(t *testing.T) {
	st, err := Open(t.TempDir() + "/dedupe.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	// 旧行：标题过期
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "mac:aa", IP: "10.0.0.9", Port: 80, Proto: "tcp", State: "open",
		Title: "旧标题", HTTPStatus: 200, FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// 新行：标题已更新
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.0.0.9", IP: "10.0.0.9", Port: 80, Proto: "tcp", State: "open",
		Title: "新标题", HTTPStatus: 200, FirstSeen: now.Add(-2 * time.Hour), LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}

	sites, err := st.ListSites(SiteFilter{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("同一 ip:port 应只产出 1 个站点，实际 %d 个", len(sites))
	}
	if sites[0].Title != "新标题" {
		t.Fatalf("应取 last_seen 最新的那行，实际标题 %q", sites[0].Title)
	}
}

// TestSiteMetaAndPrune 人工标注能写能读，且站点消失后不留孤儿标注。
func TestSiteMetaAndPrune(t *testing.T) {
	st, err := Open(t.TempDir() + "/meta.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.Title, p.HTTPStatus = 8080, "物资管理系统", 200
	})
	sites, err := st.ListSites(SiteFilter{}, 0, 0)
	if err != nil || len(sites) != 1 {
		t.Fatalf("准备站点失败: %v / %d", err, len(sites))
	}
	key := sites[0].Key

	if err := st.UpsertSiteMeta(&model.SiteMeta{
		SiteKey: key, Name: "物资系统", Tags: []string{"业务系统", "重点"}, Note: "归属后勤",
	}); err != nil {
		t.Fatalf("写标注失败: %v", err)
	}

	sites, err = st.ListSites(SiteFilter{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sites[0].Name != "物资系统" || len(sites[0].Tags) != 2 || sites[0].Note != "归属后勤" {
		t.Fatalf("标注没读回来: %+v", sites[0])
	}

	// 按标签筛选
	tagged, err := st.ListSites(SiteFilter{Tag: "重点"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged) != 1 {
		t.Fatalf("按标签筛选应命中 1 个，实际 %d 个", len(tagged))
	}
	// 标签匹配不能是子串匹配："重点" 不该命中 "重点业务组" 以外的其他标签，
	// 这里验证的是反向：不存在的标签必须 0 命中。
	if miss, _ := st.ListSites(SiteFilter{Tag: "重"}, 0, 0); len(miss) != 0 {
		t.Fatalf("子串误命中：筛 \"重\" 命中了 %d 个站点", len(miss))
	}

	// 站点消失（端口被清）之后，标注应成为孤儿并被清掉
	if _, err := st.DeletePortsByKey("ip:10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if sites, _ := st.ListSites(SiteFilter{}, 0, 0); len(sites) != 0 {
		t.Fatalf("端口清掉后站点应消失，实际还剩 %d 个", len(sites))
	}
	n, err := st.PruneOrphanSiteMeta()
	if err != nil {
		t.Fatalf("清孤儿标注失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应清掉 1 条孤儿标注，实际 %d", n)
	}
	if tags, _ := st.ListSiteTags(); len(tags) != 0 {
		t.Fatalf("标签表应已清空，实际 %v", tags)
	}
}

// TestSiteStatsAndChanges 统计与变更视图。
func TestSiteStatsAndChanges(t *testing.T) {
	st, err := Open(t.TempDir() + "/stats.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	// 三个站点：一个新的 http、一个新的 https 自签、一个 10 天前就消失的
	seedPort(t, st, func(p *model.PortRecord) {
		p.IP, p.Port, p.Title, p.HTTPStatus = "10.0.0.2", 80, "门户", 200
		p.FirstSeen, p.LastSeen = now.Add(-time.Hour), now
	})
	seedPort(t, st, func(p *model.PortRecord) {
		p.NodeKey, p.IP, p.Port = "ip:10.0.0.3", "10.0.0.3", 443
		p.TLSCN, p.SelfSigned, p.HTTPStatus = "oa.local", true, 200
		p.FirstSeen, p.LastSeen = now.Add(-2*time.Hour), now
	})
	seedPort(t, st, func(p *model.PortRecord) {
		p.NodeKey, p.IP, p.Port = "ip:10.0.0.4", "10.0.0.4", 8080
		p.Title, p.HTTPStatus = "旧系统", 200
		// 必须超过 PortStaleAfter（30 天）才算"不在线"：这个阈值是端口 stale 的口径，
		// 站点复用同一口径，两边不能各定一套。
		p.FirstSeen, p.LastSeen = now.Add(-60*24*time.Hour), now.Add(-40*24*time.Hour)
	})

	stats, err := st.SiteStats(SiteFilter{})
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if stats.Total != 3 {
		t.Fatalf("站点总数应为 3，实际 %d", stats.Total)
	}
	if stats.Online != 2 {
		t.Fatalf("在线站点应为 2（第三个 40 天没动了，超过 %v 的 stale 阈值），实际 %d", PortStaleAfter, stats.Online)
	}
	if stats.SelfSigned != 1 {
		t.Fatalf("自签站点应为 1，实际 %d", stats.SelfSigned)
	}
	if stats.ByScheme["https"] != 1 || stats.ByScheme["http"] != 2 {
		t.Fatalf("协议分布不对: %v", stats.ByScheme)
	}
	if stats.ByPort["80"] != 1 || stats.ByPort["443"] != 1 {
		t.Fatalf("端口分布不对: %v", stats.ByPort)
	}

	since := now.Add(-7 * 24 * time.Hour)
	added, gone, err := st.SiteChanges(since, 50)
	if err != nil {
		t.Fatalf("变更查询失败: %v", err)
	}
	if len(added) != 2 {
		t.Fatalf("窗口内新增应为 2 个，实际 %d 个", len(added))
	}
	if len(gone) != 1 || gone[0].IP != "10.0.0.4" {
		t.Fatalf("窗口内消失应为 1 个（10.0.0.4），实际 %+v", gone)
	}
	// 新增和消失不能重复计入同一个站点：10.0.0.4 在窗口前就在，不该算新增。
	for _, a := range added {
		if a.IP == "10.0.0.4" {
			t.Fatal("10.0.0.4 在窗口前就存在，不该算作新增")
		}
	}
}

// TestParseSiteKey 站点标识解析（URL 路径、非法输入都要挡住）。
func TestParseSiteKey(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		ip     string
		port   int
		ok     bool
	}{
		{"http://10.0.0.1:80", "http", "10.0.0.1", 80, true},
		{"HTTPS://10.0.0.2:8443", "https", "10.0.0.2", 8443, true},
		{"http://10.0.0.1", "", "", 0, false},
		{"10.0.0.1:80", "", "", 0, false},
		{"http://10.0.0.1:70000", "", "", 0, false},
		{"http://10.0.0.1:abc", "", "", 0, false},
	}
	for _, c := range cases {
		scheme, ip, port, ok := parseSiteKey(c.in)
		if ok != c.ok || scheme != c.scheme || ip != c.ip || port != c.port {
			t.Errorf("parseSiteKey(%q) = (%q,%q,%d,%v)，期望 (%q,%q,%d,%v)",
				c.in, scheme, ip, port, ok, c.scheme, c.ip, c.port, c.ok)
		}
	}
}

// TestSiteFilterOnlineAndScheme 筛选条件（协议 / 在线 / 自签）要能真的收窄结果。
func TestSiteFilterOnlineAndScheme(t *testing.T) {
	st, err := Open(t.TempDir() + "/filter.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.Title, p.HTTPStatus = 80, "明文站", 200
		p.FirstSeen, p.LastSeen = now.Add(-time.Hour), now
	})
	seedPort(t, st, func(p *model.PortRecord) {
		p.Port, p.TLSCN, p.SelfSigned, p.HTTPStatus = 443, "tls.local", true, 200
		p.FirstSeen, p.LastSeen = now.Add(-time.Hour), now
	})
	seedPort(t, st, func(p *model.PortRecord) {
		p.NodeKey, p.IP, p.Port = "ip:10.0.0.7", "10.0.0.7", 8080
		p.Title, p.HTTPStatus = "很久没动", 200
		p.FirstSeen, p.LastSeen = now.Add(-40*24*time.Hour), now.Add(-40*24*time.Hour)
	})

	if got, _ := st.ListSites(SiteFilter{Scheme: "https"}, 0, 0); len(got) != 1 {
		t.Fatalf("https 筛选应命中 1 个，实际 %d", len(got))
	}
	if got, _ := st.ListSites(SiteFilter{Scheme: "http"}, 0, 0); len(got) != 2 {
		t.Fatalf("http 筛选应命中 2 个（80 与 8080），实际 %d", len(got))
	}
	if got, _ := st.ListSites(SiteFilter{OnlySelfSigned: true}, 0, 0); len(got) != 1 {
		t.Fatalf("自签筛选应命中 1 个，实际 %d", len(got))
	}
	if got, _ := st.ListSites(SiteFilter{OnlineOnly: true, OnlineAfter: now.Add(-PortStaleAfter)}, 0, 0); len(got) != 2 {
		t.Fatalf("在线筛选应命中 2 个，实际 %d", len(got))
	}
	if n, err := st.CountSites(SiteFilter{}); err != nil || n != 3 {
		t.Fatalf("CountSites = %d, %v（期望 3）", n, err)
	}
}
