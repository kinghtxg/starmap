package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// TestCertDaysLeftCalendarDays 证书剩余天数按**本地日历日**算，逐格精确。
//
// 为什么不是"差不多就行"：原来的实现用 now.Truncate(24h) 取今天零点，
// 在 UTC+8 下取到的是本地 08:00，于是白天访问页面时所有天数少 1。
// 区间断言（"0~11 天都算对"）完全盖住了这个偏移——它看起来永远是对的。
//
// 少 1 天的实际后果不是显示难看，是判据错位：
//   - 31 天后到期的证书被算成 30 → 误报"即将到期"；
//   - 昨天到期的证书被算成 -1 → 与"没有证书情报"的哨兵值撞车 → 漏报过期。
func TestCertDaysLeftCalendarDays(t *testing.T) {
	// 固定时区与本机无关：这条逻辑的正确性与运行环境在哪台机器上无关。
	loc := time.FixedZone("CST", 8*3600)
	// 取一天中既有代表性又不会跨日的中点（本地 13:47）。
	now := time.Date(2026, 11, 1, 13, 47, 0, 0, loc)

	cases := []struct {
		offset int // 相对今天的天数
		want   int
		why    string
	}{
		{0, 0, "今天到期"},
		{1, 1, "明天到期（偏移下会算成 0）"},
		{7, 7, "一周后"},
		{29, 29, "29 天后"},
		{30, 30, "30 天后：仍在 30 天预警窗口内"},
		{31, 31, "31 天后：偏移下会算成 30，被误标即将到期"},
		{365, 365, "一年后"},
		{-1, -1, "昨天到期：偏移下会与'无情报'的 -1 撞值"},
		{-2, -2, "过期 2 天"},
		{-30, -30, "过期 30 天"},
	}
	for _, c := range cases {
		expiry := now.AddDate(0, 0, c.offset).Format("2006-01-02")
		got := certDaysLeft(expiry, now)
		if got != c.want {
			t.Errorf("expiry=%s（%s）: 剩余 %d 天，期望 %d", expiry, c.why, got, c.want)
		}
	}

	// 没有情报与解析失败都必须给 -1，且与"昨天到期"的取值重叠——
	// 这正是调用方必须用 CertExpiry == "" 判断有无情报的原因。
	if got := certDaysLeft("", now); got != -1 {
		t.Errorf("空到期日应返回 -1，实际 %d", got)
	}
	if got := certDaysLeft("不是日期", now); got != -1 {
		t.Errorf("非法到期日应返回 -1，实际 %d", got)
	}
}

// TestCertDaysLeftTimezoneIndependent 同一时刻在不同时区看到的"剩余天数"可以不同，
// 但必须都等于**该时区下**的日历日差——不能出现时区偏移被算进天数里。
//
// 现实场景：服务部署在 UTC 容器里、浏览器在中国（UTC+8）打开页面，
// 两边对"还有几天到期"必须给出一致的答案。UTC 容器里用 Truncate 算出来会差 1 天。
func TestCertDaysLeftTimezoneIndependent(t *testing.T) {
	// 同一个瞬间，分别用两个时区表示。
	base := time.Date(2026, 11, 1, 13, 47, 0, 0, time.UTC)
	zones := []struct {
		name string
		loc  *time.Location
		now  time.Time
	}{
		{"UTC+8", time.FixedZone("CST", 8*3600), base.In(time.FixedZone("CST", 8*3600))},
		{"UTC", time.UTC, base},
		{"UTC-5", time.FixedZone("EST", -5*3600), base.In(time.FixedZone("EST", -5*3600))},
	}
	for _, z := range zones {
		// 各自时区下的"明天"。
		expiry := z.now.AddDate(0, 0, 1).Format("2006-01-02")
		if got := certDaysLeft(expiry, z.now); got != 1 {
			t.Errorf("%s（本地 %s）: 明天到期算出 %d 天，期望 1",
				z.name, z.now.Format("2006-01-02 15:04"), got)
		}
		// 各自时区下的"30 天后"，不能因为时区偏移变成 29。
		expiry = z.now.AddDate(0, 0, 30).Format("2006-01-02")
		if got := certDaysLeft(expiry, z.now); got != 30 {
			t.Errorf("%s: 30 天后到期算出 %d 天，期望 30", z.name, got)
		}
	}
}

// TestSiteRisksCertBoundaries 证书风险的三个边界：刚过期、30 天整、31 天。
//
// 这三格原来全是错的，而且错法各不相同：
//   - 刚过期（-1）被 `< -1` 挡掉 → 不报 cert_expired；
//   - 31 天被天数偏移算成 30 → 误报 cert_expiring；
//   - 没有证书情报（-1）与"刚过期"同值 → 无法区分。
func TestSiteRisksCertBoundaries(t *testing.T) {
	base := func(s model.Site) model.Site {
		s.Key, s.Scheme, s.Status, s.Title = "http://10.0.0.1:443", "https", 200, "OA"
		return s
	}

	t.Run("刚过期必须报 expired", func(t *testing.T) {
		s := base(model.Site{CertExpiry: "2026-10-31", CertDaysLeft: -1})
		if got := siteRisks(&s); !hasRisk(got, "cert_expired") {
			t.Fatalf("过期 1 天没有 cert_expired：%v", got)
		}
	})

	t.Run("过期 30 天也必须报 expired", func(t *testing.T) {
		s := base(model.Site{CertExpiry: "2026-10-02", CertDaysLeft: -30})
		if got := siteRisks(&s); !hasRisk(got, "cert_expired") {
			t.Fatalf("过期 30 天没有 cert_expired：%v", got)
		}
	})

	t.Run("今天到期算 expiring 不算 expired", func(t *testing.T) {
		s := base(model.Site{CertExpiry: "2026-11-01", CertDaysLeft: 0})
		got := siteRisks(&s)
		if !hasRisk(got, "cert_expiring") {
			t.Fatalf("今天到期没有 cert_expiring：%v", got)
		}
		if hasRisk(got, "cert_expired") {
			t.Fatalf("今天到期被误标成已过期：%v", got)
		}
	})

	t.Run("30 天整仍是 expiring", func(t *testing.T) {
		s := base(model.Site{CertExpiry: "2026-12-01", CertDaysLeft: 30})
		if got := siteRisks(&s); !hasRisk(got, "cert_expiring") {
			t.Fatalf("30 天没有 cert_expiring：%v", got)
		}
	})

	t.Run("31 天不得误报 expiring", func(t *testing.T) {
		s := base(model.Site{CertExpiry: "2026-12-02", CertDaysLeft: 31})
		if got := siteRisks(&s); hasRisk(got, "cert_expiring") {
			t.Fatalf("31 天被误报成即将到期：%v", got)
		}
	})

	t.Run("没有证书情报不参与证书评估", func(t *testing.T) {
		// CertDaysLeft 也是 -1，但 CertExpiry 为空 —— 不能被当成"过期"。
		s := base(model.Site{CertExpiry: "", CertDaysLeft: -1})
		got := siteRisks(&s)
		if hasRisk(got, "cert_expired") || hasRisk(got, "cert_expiring") {
			t.Fatalf("无证书情报却产生了证书风险标签：%v", got)
		}
	})
}

func hasRisk(risks []string, want string) bool {
	for _, r := range risks {
		if r == want {
			return true
		}
	}
	return false
}

// TestSitesCertDaysLeftEndToEnd 从端口写入到站点读出的整条链路上，天数不能偏移。
//
// 上两个用例测的是纯函数；这条测的是"scanSite 拿到的时间是不是真的被正确解析了"——
// 时间在库里是文本，聚合列还会丢掉类型亲和性，读出来走的是 parseStoredTime。
func TestSitesCertDaysLeftEndToEnd(t *testing.T) {
	st, err := Open(t.TempDir() + "/cert.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	mk := func(port int, ip string, days int) {
		seedPort(t, st, func(p *model.PortRecord) {
			p.IP, p.Port, p.HTTPStatus, p.Title = ip, port, 200, "系统"
			p.CertIssuer = "Test-CA"
			p.CertExpiry = now.AddDate(0, 0, days).Format("2006-01-02")
		})
	}
	mk(443, "10.0.0.1", 1)   // 明天
	mk(8443, "10.0.0.2", 31) // 31 天后：不得进 expiring
	mk(9443, "10.0.0.3", -1) // 昨天：必须进 expired

	sites, err := st.ListSites(SiteFilter{}, 0, 0)
	if err != nil {
		t.Fatalf("查站点失败: %v", err)
	}
	byPort := map[int]model.Site{}
	for _, s := range sites {
		byPort[s.Port] = s
	}

	if s, ok := byPort[443]; !ok {
		t.Fatal("443 站点缺失")
	} else if s.CertDaysLeft != 1 {
		t.Fatalf("明天到期读出 %d 天，期望 1", s.CertDaysLeft)
	}
	if s, ok := byPort[8443]; !ok {
		t.Fatal("8443 站点缺失")
	} else if s.CertDaysLeft != 31 {
		t.Fatalf("31 天后到期读出 %d 天，期望 31", s.CertDaysLeft)
	} else if hasRisk(s.Risk, "cert_expiring") {
		t.Fatalf("31 天后到期被误标即将到期：%v", s.Risk)
	}
	if s, ok := byPort[9443]; !ok {
		t.Fatal("9443 站点缺失")
	} else if !hasRisk(s.Risk, "cert_expired") {
		t.Fatalf("昨天到期没有 cert_expired：%v", s.Risk)
	}

	// 筛选口径与风险标签必须一致：OnlyExpired 要能捞到"昨天到期"这条。
	expired, err := st.ListSites(SiteFilter{OnlyExpired: true}, 0, 0)
	if err != nil {
		t.Fatalf("查过期站点失败: %v", err)
	}
	if len(expired) != 1 || expired[0].Port != 9443 {
		t.Fatalf("OnlyExpired 应只捞到 9443，实际 %d 条: %+v", len(expired), expired)
	}
	// 31 天后到期的不该出现在 30 天预警列表里。
	expiring, err := st.ListSites(SiteFilter{OnlyExpiring: true}, 0, 0)
	if err != nil {
		t.Fatalf("查即将到期站点失败: %v", err)
	}
	for _, s := range expiring {
		if s.Port == 8443 {
			t.Fatal("OnlyExpiring 捞到了 31 天后到期的站点")
		}
	}
}
