package api

// 站点筛选参数的解析与生效（V1.7）。
//
// 为什么要逐参数测：siteFilterFromQuery 是列表、统计、导出三个入口共用的解析器
// （见 api/sites.go 的注释）。它一旦漏解析某个参数，症状不是报错，而是
// "页面筛了自签、导出来的却是全部"——用户看到的是数据不对，排查时却找不到错。

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestSitesFilterParams 每个筛选参数都从 HTTP 入口走一遍。
func TestSitesFilterParams(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	now := time.Now()

	// 10.6.0.1:80 明文、无标题之外的标注 → untagged
	webPort(t, srv, "10.6.0.1", 80, func(p *model.PortRecord) {
		p.Title, p.Product = "综合办公平台", "泛微 e-cology"
	})
	// 10.6.0.2:443 自签、10 天后到期
	webPort(t, srv, "10.6.0.2", 443, func(p *model.PortRecord) {
		p.TLSCN, p.SelfSigned, p.CertIssuer = "oa.corp.local", true, "Corp-CA"
		p.CertExpiry = now.AddDate(0, 0, 10).Format("2006-01-02")
	})
	// 10.6.0.3:8443 已过期 5 天
	webPort(t, srv, "10.6.0.3", 8443, func(p *model.PortRecord) {
		p.TLSCN, p.CertIssuer = "old.corp.local", "Corp-CA"
		p.CertExpiry = now.AddDate(0, 0, -5).Format("2006-01-02")
	})
	// 10.6.0.4:443 已人工标注
	webPort(t, srv, "10.6.0.4", 443, func(p *model.PortRecord) {
		p.TLSCN, p.CertIssuer = "hr.corp.local", "Corp-CA"
		p.CertExpiry = now.AddDate(0, 0, 200).Format("2006-01-02")
	})
	if err := srv.d.Store.UpsertSiteMeta(&model.SiteMeta{
		SiteKey: "https://10.6.0.4:443", Name: "人事系统", Tags: []string{"业务"},
	}); err != nil {
		t.Fatalf("写标注失败: %v", err)
	}

	list := func(query string) []siteJSON {
		t.Helper()
		w := doReq(t, h, http.MethodGet, "/api/sites"+query, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 状态码 %d: %s", query, w.Code, w.Body.String())
		}
		var resp struct {
			Sites []siteJSON `json:"sites"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s 解析失败: %v", query, err)
		}
		return resp.Sites
	}
	keys := func(list []siteJSON) map[string]bool {
		out := map[string]bool{}
		for _, s := range list {
			out[s.Key] = true
		}
		return out
	}

	// 基线：4 个站点都在
	if got := len(list("")); got != 4 {
		t.Fatalf("基线站点数 = %d，期望 4", got)
	}

	t.Run("port", func(t *testing.T) {
		k := keys(list("?port=443"))
		if len(k) != 2 || !k["https://10.6.0.2:443"] || !k["https://10.6.0.4:443"] {
			t.Fatalf("port=443 结果不符: %v", k)
		}
	})

	t.Run("port 非法值必须被忽略", func(t *testing.T) {
		// 非数字或越界时**不筛**，而不是筛成空集：
		// 筛成空集的话，用户手抖输错端口会看到"一个站点都没有"，误以为数据丢了。
		for _, q := range []string{"?port=abc", "?port=99999", "?port=0", "?port=-1"} {
			if got := len(list(q)); got != 4 {
				t.Errorf("%s 应忽略（返回全部 4 条），实际 %d 条", q, got)
			}
		}
	})

	t.Run("scheme 大小写", func(t *testing.T) {
		k := keys(list("?scheme=HTTPS"))
		if len(k) != 3 {
			t.Fatalf("scheme=HTTPS 应命中 3 条 https，实际 %d: %v", len(k), k)
		}
		if k["http://10.6.0.1:80"] {
			t.Fatal("scheme=HTTPS 混进了 http 站点")
		}
		// 无法识别的 scheme 值忽略，不筛
		if got := len(list("?scheme=ftp")); got != 4 {
			t.Errorf("scheme=ftp 应忽略，实际筛出 %d 条", got)
		}
	})

	t.Run("self_signed", func(t *testing.T) {
		k := keys(list("?self_signed=1"))
		if len(k) != 1 || !k["https://10.6.0.2:443"] {
			t.Fatalf("self_signed 结果不符: %v", k)
		}
	})

	t.Run("expiring 只含 30 天内且未过期", func(t *testing.T) {
		k := keys(list("?expiring=1"))
		if !k["https://10.6.0.2:443"] {
			t.Fatalf("10 天后到期的没被筛出来: %v", k)
		}
		if k["https://10.6.0.3:8443"] {
			t.Fatal("已过期的混进了 expiring")
		}
		if k["https://10.6.0.4:443"] {
			t.Fatal("200 天后到期的混进了 expiring")
		}
	})

	t.Run("expired 只含已过期", func(t *testing.T) {
		k := keys(list("?expired=1"))
		if len(k) != 1 || !k["https://10.6.0.3:8443"] {
			t.Fatalf("expired 结果不符: %v", k)
		}
	})

	t.Run("untagged", func(t *testing.T) {
		k := keys(list("?untagged=1"))
		if k["https://10.6.0.4:443"] {
			t.Fatal("已标注的站点出现在未标注列表里")
		}
		if len(k) != 3 {
			t.Fatalf("未标注应为 3 条，实际 %d: %v", len(k), k)
		}
	})

	t.Run("online", func(t *testing.T) {
		// last_seen 都是刚刚写的，四个都该算在线
		if got := len(list("?online=1")); got != 4 {
			t.Fatalf("online 应命中 4 条，实际 %d", got)
		}
	})

	t.Run("keyword 搜产品名", func(t *testing.T) {
		k := keys(list("?keyword=" + url.QueryEscape("泛微")))
		if len(k) != 1 || !k["http://10.6.0.1:80"] {
			t.Fatalf("按产品搜索结果不符: %v", k)
		}
	})

	t.Run("tag", func(t *testing.T) {
		k := keys(list("?tag=" + url.QueryEscape("业务")))
		if len(k) != 1 || !k["https://10.6.0.4:443"] {
			t.Fatalf("按标签筛选结果不符: %v", k)
		}
		// 不存在的标签：空集，不是全部
		if got := len(list("?tag=" + url.QueryEscape("不存在的标签"))); got != 0 {
			t.Fatalf("不存在的标签应返回空集，实际 %d 条", got)
		}
	})

	t.Run("truthy 的各种写法都认", func(t *testing.T) {
		for _, v := range []string{"1", "true", "TRUE", "yes", "on", "On"} {
			k := keys(list("?self_signed=" + v))
			if len(k) != 1 {
				t.Errorf("self_signed=%s 没生效（筛出 %d 条）", v, len(k))
			}
		}
		// 明确否定的值不该生效
		for _, v := range []string{"0", "false", "no", ""} {
			k := keys(list("?self_signed=" + v))
			if len(k) != 4 {
				t.Errorf("self_signed=%q 应视为否定（返回全部），实际筛出 %d 条", v, len(k))
			}
		}
	})

	t.Run("筛选条件在统计接口同样生效", func(t *testing.T) {
		w := doReq(t, h, http.MethodGet, "/api/sites/stats?scheme=http", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("统计状态码 %d: %s", w.Code, w.Body.String())
		}
		var st model.SiteStats
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		// 只有 10.6.0.1:80 是 http；统计必须跟着筛选走，
		// 否则页面顶部显示"共 4 个站点"、下面列表只有 1 条。
		if st.Total != 1 {
			t.Fatalf("scheme=http 下统计总数 = %d，期望 1（统计没跟着筛选走）", st.Total)
		}
	})
}
