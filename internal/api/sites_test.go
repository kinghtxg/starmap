package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

// webPort 写一条"有 HTTP 响应"的端口（会被识别为站点）。
func webPort(t *testing.T, srv *Server, ip string, port int, mut func(*model.PortRecord)) {
	t.Helper()
	now := time.Now()
	p := model.PortRecord{
		NodeKey: "ip:" + ip, IP: ip, Port: port, Proto: "tcp",
		Service: "http", State: "open", Source: model.PortSourceProbe,
		HTTPStatus: 200, FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}
	if mut != nil {
		mut(&p)
	}
	if err := srv.d.Store.UpsertPort(&p); err != nil {
		t.Fatalf("写端口失败: %v", err)
	}
}

// TestSitesAPI 站点列表 / 筛选 / 统计。
func TestSitesAPI(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	webPort(t, srv, "10.1.0.1", 80, func(p *model.PortRecord) {
		p.Title, p.Server, p.Product = "综合办公平台", "nginx", "泛微 e-cology"
	})
	webPort(t, srv, "10.1.0.2", 443, func(p *model.PortRecord) {
		p.TLSCN, p.SelfSigned, p.CertIssuer = "oa.corp.local", true, "Corp-CA"
		p.CertExpiry = time.Now().AddDate(0, 0, 12).Format("2006-01-02")
	})
	// 非站点：只有 SSH banner
	if err := srv.d.Store.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.1.0.3", IP: "10.1.0.3", Port: 22, Proto: "tcp",
		Service: "ssh", State: "open", Banner: "SSH-2.0-OpenSSH_8.0",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, h, http.MethodGet, "/api/sites", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sites []siteJSON `json:"sites"`
		Count int        `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v（%s）", err, w.Body.String())
	}
	if len(resp.Sites) != 2 {
		for _, s := range resp.Sites {
			t.Logf("  %s %q", s.Key, s.Title)
		}
		t.Fatalf("站点数应为 2（80 + 443，SSH 不算），实际 %d", len(resp.Sites))
	}
	if got := w.Header().Get("X-Total-Count"); got != "2" {
		t.Fatalf("X-Total-Count 应为 2，实际 %q（前端分页依赖它）", got)
	}

	// 筛选：只 HTTPS
	w = doReq(t, h, http.MethodGet, "/api/sites?scheme=https", nil, nil)
	var onlyTLS struct {
		Sites []siteJSON `json:"sites"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &onlyTLS); err != nil {
		t.Fatal(err)
	}
	if len(onlyTLS.Sites) != 1 || onlyTLS.Sites[0].Scheme != "https" {
		t.Fatalf("https 筛选不符: %+v", onlyTLS.Sites)
	}
	// 精确断言，不用区间：这张证书是 +12 天，区间写法（0~13）正是
	// certDaysLeft 少算一天却一直没被发现的原因。
	if onlyTLS.Sites[0].CertDaysLeft != 12 {
		t.Fatalf("证书剩余天数 = %d，期望 12", onlyTLS.Sites[0].CertDaysLeft)
	}

	// 统计
	w = doReq(t, h, http.MethodGet, "/api/sites/stats", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("统计状态码 %d: %s", w.Code, w.Body.String())
	}
	var st model.SiteStats
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Total != 2 || st.SelfSigned != 1 || st.Expiring != 1 {
		t.Fatalf("统计不符: %+v", st)
	}
}

// TestSiteDetailAndMeta 详情 + 人工标注 + 校验。
func TestSiteDetailAndMeta(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	webPort(t, srv, "10.2.0.1", 8080, func(p *model.PortRecord) {
		p.Title, p.Product = "物资管理系统", "致远 A8"
	})
	// 同一台机器上的另一个端口，详情页应一并带出
	webPort(t, srv, "10.2.0.1", 3306, func(p *model.PortRecord) {
		p.Service, p.Title, p.HTTPStatus = "mysql", "", 0
		p.Banner = "5.7.30-log"
	})

	key := "http://10.2.0.1:8080"
	w := doReq(t, h, http.MethodGet, "/api/sites/detail?key="+url.QueryEscape(key), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("详情状态码 %d: %s", w.Code, w.Body.String())
	}
	var detail struct {
		Site      siteJSON `json:"site"`
		HostPorts []struct {
			Port int `json:"port"`
		} `json:"host_ports"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Site.Key != key {
		t.Fatalf("详情 key 不符: %q", detail.Site.Key)
	}
	if len(detail.HostPorts) < 2 {
		t.Fatalf("主机端口应至少 2 个，实际 %d", len(detail.HostPorts))
	}

	// 标注
	w = doReq(t, h, http.MethodPost, "/api/sites/meta", map[string]any{
		"key": key, "name": "物资系统", "department": "后勤保障部",
		"tags": []string{"业务系统", "重点"}, "note": "年度巡检",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("保存标注状态码 %d: %s", w.Code, w.Body.String())
	}

	w = doReq(t, h, http.MethodGet, "/api/sites?tag="+url.QueryEscape("重点"), nil, nil)
	var tagged struct {
		Sites []siteJSON `json:"sites"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tagged); err != nil {
		t.Fatal(err)
	}
	if len(tagged.Sites) != 1 || tagged.Sites[0].Name != "物资系统" || len(tagged.Sites[0].Tags) != 2 {
		t.Fatalf("按标签筛选结果不符: %+v", tagged.Sites)
	}
	// 归属单位必须能存能读：它是"账外资产该找谁认领"的唯一线索，
	// 存进去读不出来等于没有。
	if got := tagged.Sites[0].Department; got != "后勤保障部" {
		t.Fatalf("归属单位读回 = %q，期望 后勤保障部", got)
	}

	// 标签下拉
	w = doReq(t, h, http.MethodGet, "/api/sites/tags", nil, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "重点") {
		t.Fatalf("标签列表不符: %d %s", w.Code, w.Body.String())
	}

	// 不存在的站点不能标注（防止 site_meta 里塞垃圾行）
	w = doReq(t, h, http.MethodPost, "/api/sites/meta", map[string]any{
		"key": "http://10.9.9.9:80", "name": "不存在",
	}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("不存在的站点应 404，实际 %d: %s", w.Code, w.Body.String())
	}
	// 非法标识
	w = doReq(t, h, http.MethodPost, "/api/sites/meta", map[string]any{
		"key": "not-a-key", "name": "x",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法标识应 400，实际 %d", w.Code)
	}
	// 标签过多
	many := make([]string, 21)
	for i := range many {
		many[i] = "t" + string(rune('a'+i))
	}
	w = doReq(t, h, http.MethodPost, "/api/sites/meta", map[string]any{
		"key": key, "tags": many,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("标签超过 20 个应 400，实际 %d", w.Code)
	}

	// 清除标注
	w = doReq(t, h, http.MethodDelete, "/api/sites/meta?key="+url.QueryEscape(key), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("删除标注状态码 %d: %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, http.MethodGet, "/api/sites", nil, nil)
	var after struct {
		Sites []siteJSON `json:"sites"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	for _, s := range after.Sites {
		if s.Key == key && (s.Name != "" || len(s.Tags) != 0) {
			t.Fatalf("标注应已清除，实际 %+v", s)
		}
	}
}

// TestSiteChangesAPI 站点变更视图（新增 / 消失不能重复计入）。
func TestSiteChangesAPI(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	now := time.Now()
	webPort(t, srv, "10.3.0.1", 80, func(p *model.PortRecord) {
		p.Title = "一直在"
		p.FirstSeen, p.LastSeen = now.AddDate(0, 0, -60), now
	})
	webPort(t, srv, "10.3.0.2", 80, func(p *model.PortRecord) {
		p.Title = "新上线"
		p.FirstSeen, p.LastSeen = now.AddDate(0, 0, -1), now
	})
	webPort(t, srv, "10.3.0.3", 80, func(p *model.PortRecord) {
		p.Title = "已下线"
		p.FirstSeen, p.LastSeen = now.AddDate(0, 0, -60), now.AddDate(0, 0, -20)
	})

	w := doReq(t, h, http.MethodGet, "/api/sites/changes?days=7", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Days         int `json:"days"`
		AddedCount   int `json:"added_count"`
		RemovedCount int `json:"removed_count"`
		Added        []struct {
			Key string `json:"key"`
		} `json:"added"`
		Removed []struct {
			Key string `json:"key"`
		} `json:"removed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Days != 7 || resp.AddedCount != 1 || resp.RemovedCount != 1 {
		t.Fatalf("变更统计不符: days=%d added=%d removed=%d", resp.Days, resp.AddedCount, resp.RemovedCount)
	}
	if resp.Added[0].Key != "http://10.3.0.2:80" {
		t.Fatalf("新增站点不符: %+v", resp.Added)
	}
	if resp.Removed[0].Key != "http://10.3.0.3:80" {
		t.Fatalf("消失站点不符: %+v", resp.Removed)
	}
}

// TestSitesExportCSV 导出：BOM + 中文表头 + 公式注入防护。
//
// 页面标题直接来自被扫描主机返回的 <title>，属于外部可控内容。
// 扫到一台返回 `=cmd|'/c calc'!A0` 的设备，导出文件一打开就会执行——
// 这条用例守的就是那个前缀。
func TestSitesExportCSV(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	webPort(t, srv, "10.4.0.1", 80, func(p *model.PortRecord) {
		p.Title = `=cmd|'/c calc'!A0`
		p.Product = "nginx"
	})

	w := doReq(t, h, http.MethodGet, "/api/export/sites.csv", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("导出状态码 %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.Bytes()
	if len(body) < 3 || body[0] != 0xEF || body[1] != 0xBB || body[2] != 0xBF {
		t.Fatalf("缺少 UTF-8 BOM（中文 Excel 会整列乱码），前 3 字节 % x", body[:min(3, len(body))])
	}
	text := string(body[3:])
	header := strings.SplitN(text, "\n", 2)[0]
	if !strings.Contains(header, "站点") || !strings.Contains(header, "到期日") {
		t.Fatalf("表头缺中文列名: %s", header)
	}
	// 归属单位必须在表头里：导出的主要用途是拿出去让人认领，
	// 少了这一列，表格就没法按单位分发。
	if !strings.Contains(header, "归属单位") {
		t.Fatalf("表头缺「归属单位」列: %s", header)
	}
	if !strings.Contains(text, "'=cmd") {
		t.Fatalf("公式注入没有被转义（应前缀单引号），实际内容:\n%s", text)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "sites") {
		t.Fatalf("Content-Disposition 不含文件名: %q", cd)
	}
}

// TestReportHTML 报表：能出、且**必须转义**页面标题。
//
// 页面标题来自被扫描主机返回的 <title>，是完全外部可控的内容。
// 报表会被下载、转发、用浏览器打开，用 text/template 拼字符串等于开一个
// 比后台页面更大的 XSS 面——那些打开报表的人往往不是管理员。
func TestReportHTML(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	webPort(t, srv, "10.6.0.1", 80, func(p *model.PortRecord) {
		p.Title = `<script>alert('xss')</script>`
		p.Product = `"><img src=x onerror=alert(1)>`
	})

	w := doReq(t, h, http.MethodGet, "/api/report?days=7", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("报表状态码 %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type 不符: %q", ct)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Fatal("页面标题里的 <script> 没有被转义——报表就是一个 XSS 载体")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("转义后的内容也没出现，报表可能整段没渲染出来")
	}
	if strings.Contains(body, "<img src=x") {
		t.Fatal("属性注入没有被转义")
	}
	for _, want := range []string{"资产测绘报告", "站点风险", "窗口内站点变更"} {
		if !strings.Contains(body, want) {
			t.Fatalf("报表缺少章节: %s", want)
		}
	}
	// 零外链：内网部署常常连不上外网，引一个 CDN 就是白页
	if strings.Contains(body, "http://") && strings.Contains(body, "cdn") {
		t.Fatal("报表引用了外部资源，离线环境会白页")
	}
}

// TestReportRiskListBounded "站点风险"是一张表、一个上限，且过期项优先。
//
// 原来的实现是"即将到期查 50 条 + 已过期查 50 条"拼起来：注释写着"清单都限 50 条"，
// 实际这一节能有 100 行；更要紧的是顺序反了——已过期的证书比即将到期的紧急，
// 却排在后面，条数一多就被挤到第二页没人看。
func TestReportRiskListBounded(t *testing.T) {
	addCertSites := func(t *testing.T, srv *Server, cidr string, n, daysFrom int) {
		t.Helper()
		now := time.Now()
		for i := 1; i <= n; i++ {
			ip := fmt.Sprintf("10.%s.%d", cidr, i)
			days := daysFrom
			webPort(t, srv, ip, 443, func(p *model.PortRecord) {
				p.TLSCN, p.CertIssuer = "app.local", "Corp-CA"
				p.CertExpiry = now.AddDate(0, 0, days).Format("2006-01-02")
			})
		}
	}

	render := func(t *testing.T, h http.Handler) (expired, expiring int) {
		t.Helper()
		w := doReq(t, h, http.MethodGet, "/api/report?days=7", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("报表状态码 %d", w.Code)
		}
		body := w.Body.String()
		return strings.Count(body, ">已过期<"),
			len(regexp.MustCompile(`<span class="tag warn">\d+ 天</span>`).FindAllString(body, -1))
	}

	t.Run("过期占满上限时不再列即将到期", func(t *testing.T) {
		h, _, srv := newTaskRouter(t)
		addCertSites(t, srv, "30.0", 60, -5) // 60 个已过期
		addCertSites(t, srv, "31.0", 60, 5)  // 60 个即将到期
		expired, expiring := render(t, h)
		if expired != reportRiskLimit {
			t.Errorf("已过期行数 = %d，期望 %d", expired, reportRiskLimit)
		}
		if expiring != 0 {
			t.Errorf("过期项已占满上限，却仍列了 %d 条即将到期", expiring)
		}
	})

	t.Run("过期不足时用即将到期补足", func(t *testing.T) {
		h, _, srv := newTaskRouter(t)
		addCertSites(t, srv, "32.0", 10, -3) // 10 个已过期
		addCertSites(t, srv, "33.0", 80, 7)  // 80 个即将到期
		expired, expiring := render(t, h)
		if expired != 10 {
			t.Errorf("已过期行数 = %d，期望 10", expired)
		}
		if expiring != reportRiskLimit-10 {
			t.Errorf("即将到期行数 = %d，期望 %d（补足到上限）", expiring, reportRiskLimit-10)
		}
	})
}
