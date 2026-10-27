package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"starmap/internal/config"
	"starmap/internal/model"
)

// 安全与容量护栏用例。
//
// 这些东西平时"看不出坏"，但缺了就是上线阻断项：
// 点击劫持、MIME 嗅探、超大 body 打爆内存、密码爆破、列表接口把整表塞给浏览器。
// 每个断言对应一个真实可被利用的场景，不做"调了函数就算测过"的形式化断言。

func TestSecurityHeaders(t *testing.T) {
	cfg := testCfg()
	h := newRouterWith(t, cfg, "", false)

	// 静态页、API、404 三条路径都要带：漏一条就等于那一条没防护
	paths := []string{"/index.html", "/api/health", "/api/not-exist"}
	for _, p := range paths {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		hd := w.Header()
		tag := "[" + p + "] "
		if got := hd.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf(tag+"X-Content-Type-Options = %q，期望 nosniff", got)
		}
		if got := hd.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf(tag+"X-Frame-Options = %q，期望 DENY（防点击劫持）", got)
		}
		csp := hd.Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("%s缺少 Content-Security-Policy", tag)
		}
		// frame-ancestors 是防 iframe 套用的主力，必须显式禁止
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf(tag+"CSP 缺少 frame-ancestors 'none'：%s", csp)
		}
		// 内网产品刻意零外链，CSP 必须限制到 self，否则"零外链"只是口号
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf(tag+"CSP 缺少 default-src 'self'：%s", csp)
		}
		if got := hd.Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf(tag+"Referrer-Policy = %q，期望 same-origin", got)
		}
	}
}

func TestBodyLimitRejectsOversizedConfig(t *testing.T) {
	cfg := testCfg()
	// 必须用完整依赖（含 Detector）：putConfig 会联动 Engine/Detector，
	// 用精简 router 测出来的是 nil panic，而不是我们想验证的体积上限。
	h, _, _ := newDiscoverRouter(t, cfg)

	// 2MB + 1 字节：正好越过默认上限。用一个大字符串字段而不是嵌套数组，
	// 避免测试本身在客户端就吃掉几百 MB 内存。
	huge := `{"capture_bpf":"` + strings.Repeat("A", bodyLimitDefault) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader([]byte(huge)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大配置体应 413，实际 %d：%s", w.Code, w.Body.String())
	}
	// 正常大小的配置仍然要能保存：限流不能误伤正常使用
	small := `{"capture_bpf":"tcp port 443"}`
	req = httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(small))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("正常配置保存失败 %d：%s", w.Code, w.Body.String())
	}
}

func TestListPagingAndTotalCount(t *testing.T) {
	cfg := testCfg()
	h, st, _ := newDiscoverRouter(t, cfg)

	// 造 5 条事件
	for i := 0; i < 5; i++ {
		if _, err := st.CreateEvent(&model.RiskEvent{
			Type:      "frp",
			NodeID:    int64(i + 1),
			Title:     "测试事件 " + strconv.Itoa(i),
			Level:     "high",
			Status:    model.EventStatusPending,
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("插入事件失败: %v", err)
		}
	}

	// 不传 limit：默认上限内全量返回，并带上总数
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/events", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("列表失败 %d", w.Code)
	}
	var all []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("应有 5 条，实际 %d", len(all))
	}
	if got := w.Header().Get("X-Total-Count"); got != "" && got != "5" {
		t.Errorf("X-Total-Count = %q，期望 5", got)
	}

	// limit=2 → 只返 2 条，但总数仍是 5（前端才能提示"还有更多"）
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/events?limit=2", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("limit=2 应返回 2 条，实际 %d", len(all))
	}
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("截断时 X-Total-Count 必须给出真实总数，实际 %q", got)
	}

	// limit 超过硬上限要夹取，不能照着用户给的数字去查
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/events?limit=100000000", nil))
	if got := w.Header().Get("X-Result-Limit"); got != strconv.Itoa(listMaxLimit) {
		t.Errorf("limit 应夹取到 %d，实际 %q", listMaxLimit, got)
	}

	// 非法 limit（负数/非数字）退回默认值而不是报错或全表
	for _, bad := range []string{"-1", "abc", "0"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/events?limit="+bad, nil))
		if w.Code != http.StatusOK {
			t.Errorf("limit=%s 不应报错，实际 %d", bad, w.Code)
		}
		if got := w.Header().Get("X-Result-Limit"); got != strconv.Itoa(listDefaultLimit) {
			t.Errorf("limit=%s 应退回默认 %d，实际 %q", bad, listDefaultLimit, got)
		}
	}

	// offset 生效：第 2 页的最后一条应是最早插入的那条
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/events?limit=2&offset=3", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("offset=3 limit=2 应返回 2 条，实际 %d", len(all))
	}
}

func TestAuditLimitClamped(t *testing.T) {
	cfg := testCfg()
	h := newRouterWith(t, cfg, "", false)
	w := httptest.NewRecorder()
	// 审计表只增不减，limit 不夹取等于允许一次请求把整表读进内存
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/audit?limit=999999999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("审计列表失败 %d", w.Code)
	}
}

func TestSyncAssetsThrottled(t *testing.T) {
	cfg := testCfg()
	_, st, eng := newDiscoverRouter(t, cfg)
	s := &Server{d: Deps{Store: st, Engine: eng, Cfg: config.NewBox(cfg)}}

	// 首次调用会真的同步（此处节点为空，等于空转），记录时间戳
	s.syncAssetsThrottled()
	first := s.lastAssetSync
	if first.IsZero() {
		t.Fatal("首次同步后应记录时间戳")
	}

	// 紧接着再调：应当被节流掉，不更新时间戳
	s.syncAssetsThrottled()
	if !s.lastAssetSync.Equal(first) {
		t.Error("5 秒内重复调用不应再次同步")
	}

	// 并发调用不能把同步重入（单连接 store 下重入会互相排队拖死请求）
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.syncAssetsThrottled()
		}()
	}
	wg.Wait()
}

// TestInputValidation 写接口的字段级校验。
//
// 这些值都会原样落库并渲染到别人浏览器里：一个 1MB 的"归属单位"不会立刻崩，
// 但会让每次列表查询、每次审计翻页都变慢，且没有任何界面能把它显示完整。
func TestInputValidation(t *testing.T) {
	cfg := testCfg()
	h, st, _ := newDiscoverRouter(t, cfg)

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	longName := strings.Repeat("客", maxNameLen+1) // 按字符计：中文也要能正确判超长
	cases := []struct {
		name, path, body string
		want             int
	}{
		{"域名名超长", "/api/domains", `{"name":"` + longName + `","cidrs":["10.0.0.0/24"]}`, 400},
		{"非法网段", "/api/domains", `{"name":"办公网","cidrs":["10.0.0.0/33"]}`, 400},
		{"网段数量超限", "/api/domains",
			`{"name":"办公网","cidrs":[` + strings.Repeat(`"10.0.0.0/24",`, maxCIDRCount) + `"10.1.0.0/24"]}`, 400},
		{"非法颜色", "/api/domains", `{"name":"办公网","cidrs":["10.0.0.0/24"],"color":"red;background:url(x)"}`, 400},
		{"合法域名", "/api/domains", `{"name":"办公网","cidrs":["10.0.0.0/24"],"color":"#3370ff"}`, 201},
		{"白名单备注超长", "/api/whitelist",
			`{"kind":"ip","value":"10.0.0.1","note":"` + strings.Repeat("x", maxNoteLen+1) + `"}`, 400},
		{"白名单值超长", "/api/whitelist",
			`{"kind":"ip","value":"` + strings.Repeat("1", maxValueLen+1) + `"}`, 400},
		{"资产描述超长", "/api/assets/archive",
			`{"node_key":"mac:x","description":"` + strings.Repeat("备", maxDescLen+1) + `"}`, 400},
	}
	for _, c := range cases {
		w := post(c.path, c.body)
		if w.Code != c.want {
			t.Errorf("%s: 期望 %d，实际 %d：%s", c.name, c.want, w.Code, w.Body.String())
		}
	}

	// 复核备注超长：需要先有一条事件
	if _, err := st.CreateEvent(&model.RiskEvent{
		Type: "frp", NodeID: 1, Title: "t", Level: "high",
		Status: model.EventStatusPending, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	evs, _ := st.ListEvents("", "")
	if len(evs) == 0 {
		t.Fatal("测试事件未写入")
	}
	w := post("/api/events/"+strconv.FormatInt(evs[0].ID, 10)+"/review",
		`{"action":"confirm","note":"`+strings.Repeat("x", maxNoteLen+1)+`"}`)
	if w.Code != 400 {
		t.Errorf("超长复核备注应 400，实际 %d", w.Code)
	}
}

// TestNodeDisplayLabel 事件/审计里"关联节点"的可读性。
//
// 这条链路曾经显示的是节点主键（40、30、27…），用户既不知道是哪台设备，
// 也就无法据此去拓扑里定位——一个字段的取值错误等于整列信息无效。
func TestNodeDisplayLabel(t *testing.T) {
	cases := []struct {
		name string
		node model.Node
		want string
	}{
		{"普通单 IP", model.Node{ID: 7, IPs: []string{"10.10.1.12"}}, "10.10.1.12"},
		{"多 IP 取内网", model.Node{ID: 8, IPs: []string{"203.0.113.9", "10.10.1.5"}}, "10.10.1.5 等 2 个地址"},
		{"网段聚合", model.Node{ID: 9, IPs: []string{"10.10.1.0/24"},
			Labels: []string{"subnet-agg"}}, "网段 10.10.1.0/24"},
		{"外部网段", model.Node{ID: 10, IPs: []string{"93.184.216.0/24"},
			Labels: []string{"external-agg"}}, "外部 93.184.216.0/24"},
		{"只有 MAC", model.Node{ID: 11, MAC: "aa:bb:cc:dd:ee:ff"}, "aa:bb:cc:dd:ee:ff"},
	}
	for _, c := range cases {
		if got := nodeDisplayLabel(&c.node); got != c.want {
			t.Errorf("%s: 期望 %q，实际 %q", c.name, c.want, got)
		}
	}
	if got := nodeDisplayLabel(nil); got != "" {
		t.Errorf("nil 节点应返回空串，实际 %q", got)
	}
}
