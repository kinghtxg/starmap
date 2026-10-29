package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"starmap/internal/model"
)

// 自有情报对接的接口契约。
//
// 三条不能退让的：
//  1. 推送必须凭令牌，未配令牌一律拒收（情报是"结论"，匿名可写等于允许诬告/洗白）；
//  2. 重复推送以最新版本覆盖，旧版本不许把新结论洗回去；
//  3. 查询先本地后回源，本地库能查内网地址（不外发），回源只查公网。

func intelCfg(token string) model.SystemConfig {
	c := testCfg()
	c.IntelPushToken = token
	c.IntelRetentionDays = 90
	return c
}

func pushIntel(t *testing.T, h http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		hdr["X-Intel-Token"] = token
	}
	return doReqRaw(t, h, "POST", "/api/intel/push", []byte(body), hdr)
}

func doReqRaw(t *testing.T, h http.Handler, method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestIntelPushRequiresConfiguredToken(t *testing.T) {
	h, _ := newTestRouter(t, testCfg()) // 未配令牌
	w := pushIntel(t, h, "anything", `{"records":[{"ip":"1.2.3.4","verdict":"malicious"}]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("未配推送令牌应 403，实际 %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "推送令牌") {
		t.Fatalf("错误信息应指出缺令牌，实际 %s", w.Body.String())
	}
}

func TestIntelPushRejectsWrongToken(t *testing.T) {
	h, _ := newTestRouter(t, intelCfg("s3cret"))
	w := pushIntel(t, h, "wrong", `{"records":[{"ip":"1.2.3.4","verdict":"malicious"}]}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("错误令牌应 401，实际 %d", w.Code)
	}
}

func TestIntelPushOverwritesWithLatest(t *testing.T) {
	h, st := newTestRouter(t, intelCfg("s3cret"))

	w := pushIntel(t, h, "s3cret", `{"source":"ti-platform","records":[
		{"ip":"1.2.3.4","verdict":"malicious","score":90,"tags":["c2"],"version":1,"updated_at":"2026-10-01T00:00:00Z"},
		{"ip":"8.8.8.8","verdict":"clean","score":10,"version":1,"updated_at":"2026-10-01T00:00:00Z"}
	]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("推送失败 %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Stat model.IntelIngestStat `json:"stat"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Stat.Inserted != 2 {
		t.Fatalf("应新增 2 条，实际 %+v", resp.Stat)
	}

	// 重复推送同一条、更高版本、结论改了 → 必须覆盖
	w = pushIntel(t, h, "s3cret", `{"records":[
		{"ip":"1.2.3.4","verdict":"clean","score":5,"version":2,"updated_at":"2026-10-05T00:00:00Z"}
	]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("二次推送失败 %d", w.Code)
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Stat.Updated != 1 {
		t.Fatalf("应覆盖 1 条，实际 %+v", resp.Stat)
	}
	rec, err := st.LookupIntel("1.2.3.4")
	if err != nil || rec == nil {
		t.Fatalf("查不到记录: %v", err)
	}
	if rec.Verdict != model.VerdictClean || rec.Version != 2 {
		t.Fatalf("未覆盖为最新版本：%+v", rec)
	}
	if rec.Source != "ti-platform" {
		t.Fatalf("来源应沿用推送里的 source，实际 %q", rec.Source)
	}

	// 迟到的旧版本 → stale 且不覆盖
	w = pushIntel(t, h, "s3cret", `{"records":[
		{"ip":"1.2.3.4","verdict":"malicious","version":1,"updated_at":"2026-10-01T00:00:00Z"}
	]}`)
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Stat.Stale != 1 {
		t.Fatalf("旧版本应被拒，实际 %+v", resp.Stat)
	}
	rec, _ = st.LookupIntel("1.2.3.4")
	if rec.Verdict != model.VerdictClean {
		t.Fatalf("旧包把新结论洗回去了：%+v", rec)
	}

	// 同版本同时间、只改结论 → conflict：拒绝，且必须给出独立的提示
	// （混进 stale 会让推送方去查时钟，而问题在版本号没升）
	w = pushIntel(t, h, "s3cret", `{"records":[
		{"ip":"1.2.3.4","verdict":"malicious","score":5,"version":2,"updated_at":"2026-10-05T00:00:00Z"}
	]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("同版本冲突不该报错，应 200 + 提示，实际 %d", w.Code)
	}
	var conflict struct {
		Stat         model.IntelIngestStat `json:"stat"`
		ConflictHint string                `json:"conflict_hint"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &conflict)
	if conflict.Stat.Conflict != 1 || conflict.Stat.Updated != 0 {
		t.Fatalf("同版本不同结论应记为 conflict 且不写库，实际 %+v", conflict.Stat)
	}
	if conflict.ConflictHint == "" {
		t.Fatal("conflict 必须在响应里给出提示，否则推送方无从知道该升版本号")
	}
	if rec, _ = st.LookupIntel("1.2.3.4"); rec.Verdict != model.VerdictClean {
		t.Fatalf("同版本冲突把结论改了：%+v", rec)
	}
}

func TestIntelPushTextMode(t *testing.T) {
	h, st := newTestRouter(t, intelCfg("s3cret"))

	// 只给 IP 列表时必须指定整批判定
	w := pushIntel(t, h, "s3cret", "1.1.1.1\n2.2.2.2\n")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("裸 IP 列表未指定判定应 400，实际 %d body=%s", w.Code, w.Body.String())
	}

	hdr := map[string]string{"Content-Type": "text/plain", "X-Intel-Token": "s3cret"}
	w = doReqRaw(t, h, "POST", "/api/intel/push?verdict=malicious", []byte("# 家族: c2\n1.1.1.1\n2.2.2.2\n"), hdr)
	if w.Code != http.StatusOK {
		t.Fatalf("文本推送失败 %d body=%s", w.Code, w.Body.String())
	}
	if r, _ := st.LookupIntel("1.1.1.1"); r == nil || r.Verdict != model.VerdictMalicious {
		t.Fatalf("文本推送未入库：%+v", r)
	}

	// CSV 带列：指标,判定,分值,标签
	w = doReqRaw(t, h, "POST", "/api/intel/push",
		[]byte("indicator,verdict,score,tags\n3.3.3.3,恶意,88,c2|scan\n"), hdr)
	if w.Code != http.StatusOK {
		t.Fatalf("CSV 推送失败 %d body=%s", w.Code, w.Body.String())
	}
	r, _ := st.LookupIntel("3.3.3.3")
	if r == nil || r.Verdict != model.VerdictMalicious || r.Score != 88 || len(r.Tags) != 2 {
		t.Fatalf("CSV 解析不符合预期：%+v", r)
	}
}

func TestIntelLookupPrefersLocal(t *testing.T) {
	var hits int32
	srv := fakeTI(t, &hits) // 回源接口：若被调用就会 +1
	cfg := intelCfg("")
	cfg.TIEnabled = true
	cfg.TIEndpoint = srv.URL + "/lookup?ip={ip}"
	h, st := newTestRouter(t, cfg)
	seedTopology(t, h)

	pub := findNode(t, h, func(m map[string]any) bool {
		ips := nodeIPs(m)
		return len(ips) > 0 && strings.HasPrefix(ips[0], "203.0.113.")
	})
	ip := nodeIPs(pub)[0]
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{{
		Indicator: ip, Verdict: model.VerdictMalicious, Score: 99,
		Tags: []string{"c2"}, Source: "ti-platform", Version: 1, UpdatedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, h, "GET", tiPath(nodeID(pub)), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("查询失败 %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Source string             `json:"source"`
		Record *model.IntelRecord `json:"record"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Source != "local" {
		t.Fatalf("本地有记录时不该回源，实际 source=%q", resp.Source)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("本地命中却发生了 %d 次回源请求", got)
	}
	if resp.Record == nil || resp.Record.Verdict != model.VerdictMalicious {
		t.Fatalf("返回记录不对：%+v", resp.Record)
	}
}

func TestIntelHitHighlightsNodeAndWhitelistClears(t *testing.T) {
	h, st := newTestRouter(t, intelCfg(""))
	seedTopology(t, h)

	priv := findNode(t, h, func(m map[string]any) bool {
		ips := nodeIPs(m)
		return len(ips) > 0 && strings.HasPrefix(ips[0], "10.")
	})
	ip := nodeIPs(priv)[0]

	// 内网地址的情报只可能来自推送（本地库），这正是失陷主机场景
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{{
		Indicator: ip, Verdict: model.VerdictMalicious, Score: 95,
		Source: "edr", Version: 1, UpdatedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	got := findNode(t, h, func(m map[string]any) bool { return nodeID(m) == nodeID(priv) })
	if got["Highlight"] != true {
		t.Fatalf("命中毒性情报的内网主机应标红，实际 Highlight=%v", got["Highlight"])
	}
	if got["IntelVerdict"] != model.VerdictMalicious {
		t.Fatalf("节点应带上情报结论，实际 %v", got["IntelVerdict"])
	}

	// 加白后不再标红（白名单是消红的唯一出口）
	if w := doReq(t, h, "POST", "/api/whitelist",
		map[string]any{"kind": "ip", "value": ip, "note": "自查确认"}, nil); w.Code != http.StatusCreated {
		t.Fatalf("加白失败 %d body=%s", w.Code, w.Body.String())
	}
	got = findNode(t, h, func(m map[string]any) bool { return nodeID(m) == nodeID(priv) })
	if got["Highlight"] == true {
		t.Fatal("已加白的节点不该再标红")
	}
	if got["IntelVerdict"] != model.VerdictMalicious {
		t.Fatal("加白不能改写情报事实：IntelVerdict 应保持")
	}
}

func TestIntelStatsEndpoint(t *testing.T) {
	h, st := newTestRouter(t, intelCfg("s3cret"))
	if _, err := st.UpsertIntelBatch([]model.IntelRecord{
		{Indicator: "1.2.3.4", Verdict: model.VerdictMalicious, Source: "ti", Version: 1, UpdatedAt: time.Now().UTC()},
		{Indicator: "5.6.7.8", Verdict: model.VerdictClean, Source: "ti", Version: 1, UpdatedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatal(err)
	}
	w := doReq(t, h, "GET", "/api/intel/stats", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("统计接口失败 %d", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 2 {
		t.Fatalf("总数应为 2，实际 %v", resp["total"])
	}
	if resp["push_token_set"] != true {
		t.Fatalf("应报告令牌已配置，实际 %v", resp["push_token_set"])
	}
	if resp["remote_enabled"] != false {
		t.Fatalf("未开回源时应报告 false，实际 %v", resp["remote_enabled"])
	}
}

// 保底：情报库为空时出图不受影响（annotateIntel 不该让拓扑 500）。
func TestTopologyWithoutIntel(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	seedTopology(t, h)
	if w := doReq(t, h, "GET", "/api/topology", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("空情报库下拓扑应正常，实际 %d", w.Code)
	}
}
