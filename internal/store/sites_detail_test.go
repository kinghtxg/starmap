package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// seedSite 造一个站点（有 HTTP/S 应用层响应的 open 端口）。
func seedSite(t *testing.T, st *Store, ip string, port int, f func(*model.PortRecord)) {
	t.Helper()
	now := time.Now()
	seedPort(t, st, func(p *model.PortRecord) {
		p.IP, p.NodeKey = ip, "ip:"+ip
		p.Port, p.HTTPStatus, p.Title = port, 200, "系统"
		p.FirstSeen, p.LastSeen = now.Add(-time.Hour), now
		if f != nil {
			f(p)
		}
	})
}

// TestGetSiteContract GetSite 的三条契约。
//
// 为什么它值得单独测：ListSites 与 GetSite 是两条完全不同的 SQL 路径
// （前者走 CTE + 聚合 + 分页，后者按 ip+port+scheme 精确命中），
// 详情页与"标注前校验站点存在"都依赖后者。它还有一条调用方必须依赖的契约：
// **找不到时返回 (nil, nil) 而不是错误** —— 上层靠它区分 404（站点没了）
// 与 500（库出问题）。把两种情况混成 error，用户手误关掉一个标签就会看到"服务异常"。
func TestGetSiteContract(t *testing.T) {
	st, err := Open(t.TempDir() + "/getsite.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	seedSite(t, st, "10.3.0.1", 80, func(p *model.PortRecord) {
		p.Server, p.Product, p.Version = "nginx", "nginx", "1.24"
	})
	seedSite(t, st, "10.3.0.1", 443, func(p *model.PortRecord) {
		p.TLSCN, p.CertIssuer = "oa.corp.local", "Corp-CA"
		p.CertExpiry = time.Now().AddDate(0, 0, 90).Format("2006-01-02")
		p.TLSNames = []string{"oa.corp.local"}
	})

	t.Run("命中", func(t *testing.T) {
		s, err := st.GetSite("http://10.3.0.1:80")
		if err != nil {
			t.Fatalf("查询报错: %v", err)
		}
		if s == nil {
			t.Fatal("站点存在却返回 nil")
		}
		if s.Key != "http://10.3.0.1:80" || s.Scheme != "http" || s.Port != 80 {
			t.Fatalf("站点字段不符: %+v", s)
		}
		if s.Server != "nginx" || s.Product != "nginx" {
			t.Fatalf("指纹没带出来: %+v", s)
		}
		// 时间必须能解析出来，不能是零值（聚合列的类型亲和性会丢）
		if s.LastSeen.IsZero() || s.FirstSeen.IsZero() {
			t.Fatalf("时间没解析出来: first=%v last=%v", s.FirstSeen, s.LastSeen)
		}
	})

	t.Run("https 站点", func(t *testing.T) {
		s, err := st.GetSite("https://10.3.0.1:443")
		if err != nil || s == nil {
			t.Fatalf("https 站点没查到: err=%v site=%v", err, s)
		}
		if s.Scheme != "https" || s.TLSCN != "oa.corp.local" {
			t.Fatalf("https 字段不符: %+v", s)
		}
		if len(s.TLSNames) != 1 || s.TLSNames[0] != "oa.corp.local" {
			t.Fatalf("SAN 没解析出来: %v", s.TLSNames)
		}
	})

	t.Run("scheme 不符必须落空", func(t *testing.T) {
		// 443 是 https 站点，用 http:// 去查不能命中——否则同一台机器的
		// 两个 scheme 会互相串，详情页可能拿错证书信息。
		s, err := st.GetSite("http://10.3.0.1:443")
		if err != nil {
			t.Fatalf("scheme 不符不该报错: %v", err)
		}
		if s != nil {
			t.Fatalf("http:// 命中了 https 站点: %+v", s)
		}
	})

	t.Run("站点不存在返回 nil,nil", func(t *testing.T) {
		s, err := st.GetSite("http://10.99.99.99:80")
		if err != nil {
			t.Fatalf("不存在的站点应返回 nil,nil，实际报错: %v", err)
		}
		if s != nil {
			t.Fatalf("不存在的站点却返回了 %+v", s)
		}
	})

	t.Run("非法标识报错", func(t *testing.T) {
		for _, key := range []string{"not-a-key", "http://", "://10.0.0.1:80", "10.0.0.1:80", "http://10.0.0.1:abc", "http://10.0.0.1:99999", "http://10.0.0.1:0"} {
			if _, err := st.GetSite(key); err == nil {
				t.Errorf("%q 应报格式错误，实际通过", key)
			}
		}
	})
}

// TestDeleteSiteMetaContract 删除标注的返回值必须能区分"删掉了"与"本来就没有"。
//
// 界面上两者都算成功，但审计日志与自动化脚本需要真实计数；
// 返回 0 却当成删除成功，会让人误以为"这个标注刚才还在"。
func TestDeleteSiteMetaContract(t *testing.T) {
	st, err := Open(t.TempDir() + "/delmeta.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	if err := st.UpsertSiteMeta(&model.SiteMeta{
		SiteKey: "http://10.4.0.1:80", Name: "门户", Tags: []string{"对外"},
	}); err != nil {
		t.Fatalf("写标注失败: %v", err)
	}

	n, err := st.DeleteSiteMeta("http://10.4.0.1:80")
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("删除条数 = %d，期望 1", n)
	}
	// 再删一次：不该报错，但计数必须是 0
	n, err = st.DeleteSiteMeta("http://10.4.0.1:80")
	if err != nil {
		t.Fatalf("重复删除不该报错: %v", err)
	}
	if n != 0 {
		t.Fatalf("重复删除计数 = %d，期望 0", n)
	}
}

// TestListSiteTagsGroupsByTag 标签统计要按标签聚合，且跳过空标注。
func TestListSiteTagsGroupsByTag(t *testing.T) {
	st, err := Open(t.TempDir() + "/tags.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	write := func(key string, tags []string) {
		if err := st.UpsertSiteMeta(&model.SiteMeta{SiteKey: key, Tags: tags}); err != nil {
			t.Fatalf("写标注失败: %v", err)
		}
	}
	write("http://10.5.0.1:80", []string{"业务", "重点"})
	write("http://10.5.0.2:80", []string{"业务"})
	write("http://10.5.0.3:80", nil) // 空标注：不该产生标签

	got, err := st.ListSiteTags()
	if err != nil {
		t.Fatalf("查标签失败: %v", err)
	}
	if got["业务"] != 2 {
		t.Errorf("「业务」出现 %d 次，期望 2", got["业务"])
	}
	if got["重点"] != 1 {
		t.Errorf("「重点」出现 %d 次，期望 1", got["重点"])
	}
	if _, ok := got[""]; ok {
		t.Errorf("空标签不该进统计: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("标签种类 = %d，期望 2（%v）", len(got), got)
	}
}

// TestScanTimeToleratesGarbage 时间解析失败要退化成零值，而不是 panic 或抛错。
//
// 库里的文本是可能被人改过的（人工修库、第三方同步脚本），
// 一行脏数据不该让整个站点列表打不开。
func TestScanTimeToleratesGarbage(t *testing.T) {
	if got := scanTime(""); !got.IsZero() {
		t.Errorf("空串应为零值，实际 %v", got)
	}
	if got := scanTime("2026-13-45 99:99:99"); !got.IsZero() {
		t.Errorf("非法日期应为零值，实际 %v", got)
	}
	// 正常值必须解析出来（回归守卫：别为了容错把正常路径也吞了）
	got := scanTime("2026-11-01 05:00:00 +0000 UTC")
	want := time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("正常时间解析成 %v，期望 %v", got, want)
	}
}
