// Package e2e 端到端集成测试（SPEC §8 / ACCEPTANCE 11.3）：
// 启动完整服务（httptest 真实 HTTP）→ 依次上传 5 个合成 PCAP →
// 断言 4 类风险事件生成、normal 不产事件、拓扑节点/边、review 三操作 + 审计留痕、
// 误报自动加白、重复上传事件去重。
package e2e

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"starmap/internal/api"
	"starmap/internal/detect"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
	"starmap/testdata/pcapgen"
)

type env struct {
	h  http.Handler
	st *store.Store
	t  *testing.T
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := model.SystemConfig{
		AgingSeconds: 86400, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
		ReverseProxyHosts: 10, LongConnSeconds: 3600, HeartbeatMaxBytes: 64,
		ListenAddr: ":0", DBPath: ":memory:",
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := topology.New(cfg)
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	det := detect.New(st, eng, cfg)
	det.SessionsFunc = agg.Finalize
	rvw := review.New(st, eng)
	scanner := probe.New(eng)
	h := api.NewRouter(api.Deps{
		Store: st, Engine: eng, Detector: det, Reviewer: rvw, Scanner: scanner,
		Cfg: &cfg, Aggregator: agg, Version: "V1.0-test",
	})
	return &env{h: h, st: st, t: t}
}

func (e *env) do(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func (e *env) list(path string) []map[string]any {
	e.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 200 {
		e.t.Fatalf("GET %s → %d: %s", path, w.Code, w.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		e.t.Fatalf("GET %s 响应非 JSON 数组: %s", path, w.Body.String())
	}
	return out
}

func (e *env) upload(name string, data []byte) map[string]any {
	e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		e.t.Fatal(err)
	}
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest("POST", "/api/ingest/pcap", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 200 {
		e.t.Fatalf("上传 %s 失败 %d: %s", name, w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m
}

func countEvents(evs []map[string]any, typ, status string) int {
	n := 0
	for _, ev := range evs {
		if (typ == "" || ev["Type"] == typ) && (status == "" || ev["Status"] == status) {
			n++
		}
	}
	return n
}

// TestE2EMatrix 5 场景 × 事件断言主矩阵。
func TestE2EMatrix(t *testing.T) {
	e := newEnv(t)

	// 预置 4 个网络域（与 cmd/starmap 默认一致）
	for _, d := range []map[string]any{
		{"Name": "gov", "CIDRs": []string{"10.0.0.0/8"}, "Color": "#38BDF8"},
		{"Name": "office", "CIDRs": []string{"172.16.0.0/12"}, "Color": "#4ADE80"},
		{"Name": "internet", "CIDRs": []string{"0.0.0.0/0"}, "Color": "#94A3B8"},
		{"Name": "prod", "CIDRs": []string{"192.168.0.0/16"}, "Color": "#FB923C"},
	} {
		code, m := e.do("POST", "/api/domains", d)
		if code != 201 {
			t.Fatalf("建域失败 %d: %v", code, m)
		}
	}

	gen := pcapgen.Scenarios()
	data := map[string][]byte{}
	for name, g := range gen {
		b, err := g()
		if err != nil {
			t.Fatalf("生成 %s: %v", name, err)
		}
		if len(b) > 500*1024 {
			t.Fatalf("%s 超过 500KB 限制: %d", name, len(b))
		}
		data[name] = b
	}

	// ① 正常办公：不产生任何事件
	e.upload("normal_office.pcap", data["normal_office.pcap"])
	if evs := e.list("/api/events"); len(evs) != 0 {
		t.Fatalf("normal 场景不应产生事件，实际 %d 个: %v", len(evs), evs)
	}

	// ② FRP
	resp := e.upload("frp_tunnel.pcap", data["frp_tunnel.pcap"])
	if resp["new_events"].(float64) < 1 {
		t.Fatalf("frp 场景应产生事件: %v", resp)
	}
	evs := e.list("/api/events?type=frp&status=pending")
	if len(evs) != 1 {
		t.Fatalf("应有 1 个 pending frp 事件，实际 %d", len(evs))
	}
	frpEv := evs[0]
	if frpEv["Level"] != "high" {
		t.Fatalf("三项全中应为 high，实际 %v", frpEv["Level"])
	}
	evd := frpEv["Evidence"].(map[string]any)
	if evd["ja_match"] != "true" || evd["long_conn"] != "true" || evd["heartbeat"] != "true" {
		t.Fatalf("frp 证据应三项全中: %v", evd)
	}

	// ③ Clash
	e.upload("clash_proxy.pcap", data["clash_proxy.pcap"])
	if n := countEvents(e.list("/api/events?status=pending"), "clash", ""); n != 1 {
		t.Fatalf("应有 1 个 clash 事件，实际 %d", n)
	}

	// ④ 反代
	e.upload("reverse_proxy.pcap", data["reverse_proxy.pcap"])
	rpEvs := e.list("/api/events?type=reverse_proxy")
	if len(rpEvs) != 1 {
		t.Fatalf("应有 1 个 reverse_proxy 事件，实际 %d", len(rpEvs))
	}
	if rpEvs[0]["Evidence"].(map[string]any)["host_count"] != "12" {
		t.Fatalf("反代证据 host_count 应为 12: %v", rpEvs[0]["Evidence"])
	}

	// ⑤ 跨网域融合
	e.upload("multi_net.pcap", data["multi_net.pcap"])
	mnEvs := e.list("/api/events?type=multi_net")
	if len(mnEvs) != 1 {
		t.Fatalf("应有 1 个 multi_net 事件，实际 %d", len(mnEvs))
	}
	if mnEvs[0]["Level"] != "high" {
		t.Fatalf("multi_net 应为 high: %v", mnEvs[0]["Level"])
	}

	// 拓扑断言：有节点和边
	code, topo := e.do("GET", "/api/topology", nil)
	if code != 200 {
		t.Fatalf("topology %d", code)
	}
	if len(topo["Nodes"].([]any)) == 0 || len(topo["Edges"].([]any)) == 0 {
		t.Fatalf("拓扑应有节点和边: %v", topo["Stats"])
	}

	// 去重：全部 5 个 PCAP 重复上传，事件总数不翻倍（§10.5，全部 pending 时均在去重窗口内）
	before := len(e.list("/api/events"))
	for _, name := range []string{"normal_office.pcap", "frp_tunnel.pcap", "clash_proxy.pcap", "reverse_proxy.pcap", "multi_net.pcap"} {
		e.upload(name, data[name])
	}
	after := len(e.list("/api/events"))
	if after != before {
		t.Fatalf("重复上传事件不应翻倍：%d → %d", before, after)
	}

	// review 三操作：confirm / false_positive / defer → 状态流转 + 审计留痕
	all := e.list("/api/events")
	if len(all) != 4 {
		t.Fatalf("应共 4 个事件，实际 %d", len(all))
	}
	byType := map[string]map[string]any{}
	for _, ev := range all {
		byType[ev["Type"].(string)] = ev
	}
	review := func(typ, action string) map[string]any {
		id := int64(byType[typ]["ID"].(float64))
		code, m := e.do("POST", "/api/events/"+strconv.FormatInt(id, 10)+"/review",
			map[string]string{"action": action, "note": "e2e-" + action, "reviewer": "tester"})
		if code != 200 {
			t.Fatalf("review %s/%s 失败 %d: %v", typ, action, code, m)
		}
		return m
	}
	if r := review("frp", "confirm"); r["Status"] != "confirmed" {
		t.Fatalf("confirm 后状态异常: %v", r["Status"])
	}
	wlBefore := len(e.list("/api/whitelist"))
	if r := review("clash", "false_positive"); r["Status"] != "false_positive" {
		t.Fatalf("false_positive 后状态异常: %v", r["Status"])
	}
	wlAfter := len(e.list("/api/whitelist"))
	if wlAfter <= wlBefore {
		t.Fatalf("误报操作后白名单应自动新增（%d → %d）", wlBefore, wlAfter)
	}
	if r := review("multi_net", "defer"); r["Status"] != "deferred" {
		t.Fatalf("defer 后状态异常: %v", r["Status"])
	}

	// 审计留痕：三操作 + 自动加白 + 上传接入
	audits := e.list("/api/audit")
	actions := map[string]int{}
	for _, a := range audits {
		actions[a["Action"].(string)]++
	}
	for _, want := range []string{"event_confirm", "event_false_positive", "event_defer", "whitelist_create", "ingest_pcap"} {
		if actions[want] == 0 {
			t.Fatalf("审计缺少 %s，实际: %v", want, actions)
		}
	}
}

// TestE2EBadPCAP 损坏文件返回 4xx 不崩溃（ACCEPTANCE 1.3）。
func TestE2EBadPCAP(t *testing.T) {
	e := newEnv(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "bad.pcap")
	fw.Write([]byte("this is not a pcap file............"))
	mw.Close()
	req := httptest.NewRequest("POST", "/api/ingest/pcap", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("损坏 PCAP 应 4xx，实际 %d", w.Code)
	}
}
