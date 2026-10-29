package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"starmap/internal/model"
	"starmap/internal/topology"
)

// 威胁情报接入的 API 层测试。
//
// 这里守的是三条不能退让的边界：
//  1. 没配接口时，前端拿到的是「未配置」而不是一个 500；
//  2. 内网地址一个字节都不许外发（这不是"最好别"，是硬约束）；
//  3. 标红是结论、归属是事实——加白只能压掉红色，不能改写"这台在国外"。

// fakeTI 起一个假的威胁情报接口，记录被调用次数。
func fakeTI(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = strings.TrimPrefix(r.URL.Path, "/")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":95,"verdict":"malicious","tags":["c2","scan"]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tiTestCfg(endpoint string) model.SystemConfig {
	c := testCfg()
	c.TIEnabled = true
	c.TIEndpoint = endpoint
	c.TITimeoutMS = 3000
	c.TICacheSeconds = 600
	return c
}

// tiPath 拼节点情报查询路径。
//
// 必须按 encodeURIComponent 的规则转义：节点 ID 里的 "/" 若原样出现在路径上，
// 会被当成路径分隔符多切一段，服务端拿到的就不是一个完整 ID 了。
func tiPath(id string) string {
	return "/api/nodes/" + url.QueryEscape(id) + "/ti"
}

// findNode 在拓扑快照里挑出第一个满足条件的节点。
func findNode(t *testing.T, h http.Handler, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	w := doReq(t, h, "GET", "/api/topology", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/topology = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Nodes []map[string]any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析拓扑失败: %v", err)
	}
	for _, n := range resp.Nodes {
		if pred(n) {
			return n
		}
	}
	t.Fatalf("拓扑里没有满足条件的节点（共 %d 个）", len(resp.Nodes))
	return nil
}

func nodeID(n map[string]any) string {
	s, _ := n["ID"].(string)
	return s
}

func nodeIPs(n map[string]any) []string {
	raw, _ := n["IPs"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// seedTopology 造一台内网主机 + 一台公网主机的拓扑。
func seedTopology(t *testing.T, h http.Handler) {
	t.Helper()
	if w := uploadPCAP(t, h, buildFRPPCAP(t, "10.1.1.5", "02:00:00:00:00:aa", 51000), "ti.pcap"); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("上传 PCAP 失败: %d %s", w.Code, w.Body.String())
	}
}

// TestLookupTIUnconfigured：没配接口要回「未配置」，让人知道去哪儿配。
func TestLookupTIUnconfigured(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	seedTopology(t, h)

	n := findNode(t, h, func(m map[string]any) bool { return len(nodeIPs(m)) > 0 })
	w := doReq(t, h, "GET", tiPath(nodeID(n)), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("未配置时应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["configured"] != false {
		t.Fatalf("configured 应为 false，实际 %v", resp["configured"])
	}
	if msg, _ := resp["message"].(string); !strings.Contains(msg, "威胁情报") {
		t.Fatalf("提示文案应说明未配置威胁情报，实际 %q", msg)
	}
}

// TestLookupTIPrivateIPNoEgress：内网地址必须被本地拦下，一次外发都不许发生。
//
// 断言 hits==0 才是这条约束的真正含义：只检查状态码是 400 并不能证明没发出去
// （可能先发了、再因为别的原因报错）。
func TestLookupTIPrivateIPNoEgress(t *testing.T) {
	var hits int32
	srv := fakeTI(t, &hits)
	h, _ := newTestRouter(t, tiTestCfg(srv.URL+"/lookup?ip={ip}"))
	seedTopology(t, h)

	n := findNode(t, h, func(m map[string]any) bool {
		ips := nodeIPs(m)
		return len(ips) > 0 && strings.HasPrefix(ips[0], "10.")
	})
	w := doReq(t, h, "GET", tiPath(nodeID(n)), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("内网地址应 400，实际 %d body=%s", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("内网地址产生了 %d 次外发请求，等于把内网结构泄露给第三方", got)
	}
}

// TestLookupTISuccessAndCache：公网节点能查到结果，第二次走缓存不再外发。
func TestLookupTISuccessAndCache(t *testing.T) {
	var hits int32
	srv := fakeTI(t, &hits)
	h, _ := newTestRouter(t, tiTestCfg(srv.URL+"/lookup?ip={ip}"))
	seedTopology(t, h)

	n := findNode(t, h, func(m map[string]any) bool {
		ips := nodeIPs(m)
		return len(ips) > 0 && !strings.HasPrefix(ips[0], "10.") && !strings.HasPrefix(ips[0], "192.168.")
	})
	id := nodeID(n)

	w := doReq(t, h, "GET", tiPath(id), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("查询失败 %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Fatalf("ok 应为 true，实际 %v", resp["ok"])
	}
	if s, _ := resp["summary"].(string); s == "" {
		t.Fatal("缺少 summary，前端没东西可展示")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("第一次查询应外发 1 次，实际 %d", got)
	}

	// 第二次命中缓存
	if w := doReq(t, h, "GET", tiPath(id), nil, nil); w.Code != http.StatusOK {
		t.Fatalf("缓存查询失败 %d", w.Code)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("缓存未生效，第二次仍外发（累计 %d 次）", got)
	}

	// refresh=1 跳过缓存
	if w := doReq(t, h, "GET", tiPath(id)+"?refresh=1", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("强制刷新失败 %d", w.Code)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("refresh=1 应重新外发，累计应为 2，实际 %d", got)
	}
}

// TestLookupTIRejectsSubnetAggregate：网段聚合节点没有单一 IP，直接说清原因。
func TestLookupTIRejectsSubnetAggregate(t *testing.T) {
	var hits int32
	srv := fakeTI(t, &hits)
	h, _ := newTestRouter(t, tiTestCfg(srv.URL+"/lookup?ip={ip}"))

	w := doReq(t, h, "GET", tiPath("subnet:10.1.1.0/24"), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("网段聚合节点应 400，实际 %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "网段") {
		t.Fatalf("错误信息应说明是网段聚合节点，实际 %s", w.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("不该外发，实际 %d 次", got)
	}
}

// TestHighlightIsConclusionNotFact：加白消红，但不改写归属事实。
func TestHighlightIsConclusionNotFact(t *testing.T) {
	overseas := &model.Node{
		ID: 7, IPs: []string{"203.0.113.60"}, NodeKey: "ip:203.0.113.60",
		RiskLevel: model.RiskLow, Overseas: true,
	}

	nj := buildNodeJSON(overseas, nil)
	if !nj.Overseas || !nj.Highlight {
		t.Fatalf("国外节点应 Overseas+Highlight 双真，实际 overseas=%v highlight=%v",
			nj.Overseas, nj.Highlight)
	}

	// 按 IP 加白
	nj = buildNodeJSON(overseas, []model.WhitelistEntry{{Kind: "ip", Value: "203.0.113.60"}})
	if nj.Highlight {
		t.Fatal("已加白的节点不该再标红")
	}
	if !nj.Overseas {
		t.Fatal("加白不能改写归属事实：Overseas 必须仍然为 true")
	}
	if !nj.Whitelisted {
		t.Fatal("Whitelisted 应为 true，前端要靠它区分「已知资产」和「没判定出归属」")
	}
}

// TestHighlightTunnelAndRisk：疑似隧道/中高风险也要标红。
func TestHighlightTunnelAndRisk(t *testing.T) {
	cases := []struct {
		name string
		node *model.Node
		want bool
	}{
		{"普通内网主机不标红", &model.Node{ID: 1, IPs: []string{"10.1.1.5"}, RiskLevel: model.RiskLow}, false},
		{"中风险标红", &model.Node{ID: 2, IPs: []string{"10.1.1.6"}, RiskLevel: model.RiskMid}, true},
		{"高风险标红", &model.Node{ID: 3, IPs: []string{"10.1.1.7"}, RiskLevel: model.RiskHigh}, true},
		{"隧道标签标红", &model.Node{ID: 4, IPs: []string{"10.1.1.8"}, Labels: []string{"frp"}, RiskLevel: model.RiskLow}, true},
	}
	for _, c := range cases {
		if got := buildNodeJSON(c.node, nil).Highlight; got != c.want {
			t.Errorf("%s：Highlight 期望 %v 实际 %v", c.name, c.want, got)
		}
	}
}

// TestNodeWhitelistCoversExternalCIDR：外部聚合节点存的是 "8.8.8.0/24"，
// 白名单里写的是主机 IP。不剥掩码的话 net.ParseIP 返回 nil，白名单静默失效。
func TestNodeWhitelistCoversExternalCIDR(t *testing.T) {
	n := &model.Node{
		ID: 9, IPs: []string{"8.8.8.0/24"}, NodeKey: "ext:8.8.8.0/24",
		RiskLevel: model.RiskLow, Overseas: true,
	}
	wl := []model.WhitelistEntry{{Kind: "cidr", Value: "8.8.8.0/24"}}
	if !buildNodeJSON(n, wl).Whitelisted {
		t.Fatal("对 8.8.8.0/24 加白后，聚合节点应命中白名单")
	}
	// 网段不匹配时不能误命中
	wl = []model.WhitelistEntry{{Kind: "cidr", Value: "9.9.9.0/24"}}
	if buildNodeJSON(n, wl).Whitelisted {
		t.Fatal("不相关的网段不该命中白名单")
	}
}

// TestAPINodeIDRoundTrip 顺带守住 ID 契约：TI 查询靠它决定走哪条路径。
func TestAPINodeIDRoundTrip(t *testing.T) {
	cases := map[string]string{
		"42":                 "node",
		"ext:8.8.8.0/24":     "ext",
		"subnet:10.0.0.0/24": "subnet",
	}
	for id, want := range cases {
		kind, _, _ := topology.ParseAPINodeID(id)
		if kind != want {
			t.Errorf("%s 解析为 %q，期望 %q", id, kind, want)
		}
	}
}

// TestNodeDetailEncodedID：ID 里带 "/" 的节点（ext:/subnet:）必须能按编码后的路径取到。
//
// 这是 V1.5 之前就存在的暗坑：前端一直用 encodeURIComponent 拼 URL，
// 而后端按解码后的 Path 路由，%2F 变回 "/" 就多切一段 → 详情面板对公网/网段节点
// 一直是 404。加威胁情报入口必须先有这个，否则"点开看它到底有没有问题"根本点不开。
func TestNodeDetailEncodedID(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	seedTopology(t, h)

	ext := findNode(t, h, func(m map[string]any) bool {
		return strings.HasPrefix(nodeID(m), "ext:")
	})
	w := doReq(t, h, "GET", "/api/nodes/"+url.QueryEscape(nodeID(ext)), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("编码后的 ext 节点详情应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if n, ok := resp["Node"].(map[string]any); !ok || nodeID(n) != nodeID(ext) {
		t.Fatalf("返回的节点不是请求的那个：%v", resp["Node"])
	}
}
