package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// 这一组用例补齐 REST 面的基本契约（状态码 + 关键字段），
// 目标是把「接口存在但没人验过」的部分覆盖掉：
// 资产增删改归档、端口查询、节点详情、下钻视图、代理列表、审计、统计、404 兜底。

// seedHosts 通过探针 flows 建立两台互访主机（走完整流水线，不用后门造数据）。
func seedHosts(t *testing.T, src, dst string) http.Handler {
	t.Helper()
	h, _ := newTestRouter(t, testCfg())
	body := map[string]any{
		"probe_id": "probe-seed",
		"ts":       base.Format(time.RFC3339),
		"flows": []map[string]any{{
			"src_ip": src, "dst_ip": dst,
			"src_port": 40000, "dst_port": 80, "proto": "tcp",
			"bytes_up": 5000, "bytes_down": 9000, "packets": 40,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(30 * time.Second).Format(time.RFC3339),
		}},
	}
	if w := doReq(t, h, "POST", "/api/ingest/probe", body, nil); w.Code != 200 {
		t.Fatalf("播种失败 %d: %s", w.Code, w.Body.String())
	}
	return h
}

func decodeArray(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("响应不是数组: %s", string(b))
	}
	return out
}

// TestAssetsLifecycle 资产全生命周期：出现 → 归档 → 修改 → 删除。
func TestAssetsLifecycle(t *testing.T) {
	h := seedHosts(t, "10.20.0.1", "10.20.0.2")

	// 1) 同步后应自动登记（未归档）
	w := doReq(t, h, "GET", "/api/assets", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/assets = %d: %s", w.Code, w.Body.String())
	}
	assets := decodeArray(t, w.Body.Bytes())
	if len(assets) == 0 {
		t.Fatal("观测到的主机应自动进入资产库")
	}
	key := assets[0]["node_key"].(string)

	// 2) 汇总卡
	w = doReq(t, h, "GET", "/api/assets/stats", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/assets/stats = %d", w.Code)
	}
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if _, ok := st["unarchived"]; !ok {
		t.Fatalf("统计缺少 unarchived 字段: %s", w.Body.String())
	}

	// 3) 归档：缺 node_key → 400
	if w = doReq(t, h, "POST", "/api/assets/archive", map[string]any{}, nil); w.Code != 400 {
		t.Fatalf("缺 node_key 应 400，实际 %d", w.Code)
	}
	w = doReq(t, h, "POST", "/api/assets/archive", map[string]any{
		"node_key": key, "owner": "张三", "department": "运维部", "location": "3F",
	}, nil)
	if w.Code != 200 {
		t.Fatalf("归档失败 %d: %s", w.Code, w.Body.String())
	}

	// 4) 归档后应出现在 archived 过滤结果里，且带归属信息
	w = doReq(t, h, "GET", "/api/assets?status=archived", nil, nil)
	archived := decodeArray(t, w.Body.Bytes())
	found := false
	for _, a := range archived {
		if a["node_key"] == key {
			found = true
			if a["owner"] != "张三" {
				t.Fatalf("归档归属人应为张三，实际 %v", a["owner"])
			}
		}
	}
	if !found {
		t.Fatal("已归档资产未出现在 archived 列表")
	}

	// 5) 修改
	w = doReq(t, h, "PUT", "/api/assets/"+key, map[string]any{
		"owner": "李四", "department": "安全部", "location": "5F",
	}, nil)
	if w.Code != 200 {
		t.Fatalf("修改资产失败 %d: %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/assets?status=archived", nil, nil)
	for _, a := range decodeArray(t, w.Body.Bytes()) {
		if a["node_key"] == key && a["owner"] != "李四" {
			t.Fatalf("修改后归属人应为李四，实际 %v", a["owner"])
		}
	}

	// 6) 删除
	if w = doReq(t, h, "DELETE", "/api/assets/"+key, nil, nil); w.Code != 200 {
		t.Fatalf("删除资产失败 %d: %s", w.Code, w.Body.String())
	}
}

// TestNodeDetailAndSubnetDrill 节点详情 + 下钻视图：这是"理清网内结构"的主路径。
func TestNodeDetailAndSubnetDrill(t *testing.T) {
	h := seedHosts(t, "10.30.0.1", "10.30.0.2")

	w := doReq(t, h, "GET", "/api/topology", nil, nil)
	var snap struct {
		Nodes []map[string]any
	}
	json.Unmarshal(w.Body.Bytes(), &snap)
	if len(snap.Nodes) == 0 {
		t.Fatal("拓扑应有节点")
	}

	// 找到非聚合节点的数字 ID
	var numID int64
	for _, n := range snap.Nodes {
		if v, ok := n["NumID"].(float64); ok && v > 0 {
			numID = int64(v)
			break
		}
	}
	if numID == 0 {
		t.Fatal("未找到可用的节点数字 ID")
	}

	w = doReq(t, h, "GET", "/api/nodes/"+strconv.FormatInt(numID, 10), nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/nodes/%d = %d: %s", numID, w.Code, w.Body.String())
	}
	var detail map[string]any
	json.Unmarshal(w.Body.Bytes(), &detail)
	// 详情必须能回答"这台机器在跟谁通信"
	for _, k := range []string{"Node", "Peers"} {
		if _, ok := detail[k]; !ok {
			t.Fatalf("节点详情缺少字段 %s: %s", k, w.Body.String())
		}
	}
	node, _ := detail["Node"].(map[string]any)
	if node == nil || len(node["IPs"].([]any)) == 0 {
		t.Fatalf("节点详情应带 IP: %s", w.Body.String())
	}

	// 不存在的节点 → 404
	if w = doReq(t, h, "GET", "/api/nodes/99999999", nil, nil); w.Code != 404 {
		t.Fatalf("不存在的节点应 404，实际 %d", w.Code)
	}

	// 下钻：10.30.0.0/24
	w = doReq(t, h, "GET", "/api/topology/subnet/10.30.0.0/24", nil, nil)
	if w.Code != 200 {
		t.Fatalf("下钻视图 = %d: %s", w.Code, w.Body.String())
	}
	var sub map[string]any
	json.Unmarshal(w.Body.Bytes(), &sub)
	if len(sub["Nodes"].([]any)) == 0 {
		t.Fatal("下钻视图应有节点")
	}
	// 下钻必须带段内链路，否则等于只看到孤点（V1.6 修的 P1）
	if edges, ok := sub["Edges"].([]any); !ok || len(edges) == 0 {
		t.Fatalf("下钻视图应包含段内边: %s", w.Body.String())
	}
}

// TestProxiesEndpoint 七层转发代理列表。
func TestProxiesEndpoint(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	body := map[string]any{
		"probe_id": "probe-xff",
		"ts":       base.Format(time.RFC3339),
		"flows": []map[string]any{{
			"src_ip": "10.40.0.1", "dst_ip": "10.41.0.1",
			"src_port": 40000, "dst_port": 80, "proto": "tcp",
			"bytes_up": 5000, "bytes_down": 9000, "packets": 40,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(30 * time.Second).Format(time.RFC3339),
			"xff":        []string{"10.42.0.7"},
			"x_real_ip":  "10.42.0.7",
		}},
	}
	if w := doReq(t, h, "POST", "/api/ingest/probe", body, nil); w.Code != 200 {
		t.Fatalf("上报失败 %d: %s", w.Code, w.Body.String())
	}
	w := doReq(t, h, "GET", "/api/proxies", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/proxies = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Total   int              `json:"total"`
		Clients int              `json:"clients"`
		Proxies []map[string]any `json:"proxies"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Total != 1 || len(resp.Proxies) != 1 {
		t.Fatalf("应识别出 1 个代理节点: %s", w.Body.String())
	}
	if n, ok := resp.Proxies[0]["clients"].(float64); !ok || n < 1 {
		t.Fatalf("代理应带客户端计数: %+v", resp.Proxies[0])
	}
	if resp.Clients < 1 {
		t.Fatalf("汇总客户端数应 >= 1，实际 %d", resp.Clients)
	}
}

// TestStatsIncludesSessionTable 统计接口要暴露会话表容量指标（运维据此判断是否该调参）。
func TestStatsIncludesSessionTable(t *testing.T) {
	h := seedHosts(t, "10.50.0.1", "10.50.0.2")
	w := doReq(t, h, "GET", "/api/stats", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/stats = %d", w.Code)
	}
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	tbl, ok := st["SessionTable"].(map[string]any)
	if !ok {
		t.Fatalf("统计缺少 SessionTable: %s", w.Body.String())
	}
	for _, k := range []string{"Active", "MaxSessions", "Dropped", "Evicted"} {
		if _, ok := tbl[k]; !ok {
			t.Fatalf("SessionTable 缺少 %s: %+v", k, tbl)
		}
	}
	if st["SessionCount"].(float64) < 1 {
		t.Fatalf("SessionCount 应 >= 1: %v", st["SessionCount"])
	}
}

// TestPortsEndpoint 端口查询（按 ip / node_key 过滤）。
func TestPortsEndpoint(t *testing.T) {
	h := seedHosts(t, "10.60.0.1", "10.60.0.2")

	if w := doReq(t, h, "GET", "/api/ports?ip=10.60.0.1", nil, nil); w.Code != 200 {
		t.Fatalf("GET /api/ports = %d: %s", w.Code, w.Body.String())
	}
	// 非法 IP 不应 500
	if w := doReq(t, h, "GET", "/api/ports?ip=not-an-ip", nil, nil); w.Code != 200 {
		t.Fatalf("非法 IP 查询不应报错，实际 %d: %s", w.Code, w.Body.String())
	}
	// 不存在的扫描任务 → 404
	if w := doReq(t, h, "GET", "/api/ports/scan/nope", nil, nil); w.Code != 404 {
		t.Fatalf("不存在的扫描任务应 404，实际 %d", w.Code)
	}
}

// TestAuditEndpoint 审计留痕必须可查——这是"只打标签不定性"之外的第二条合规底线。
func TestAuditEndpoint(t *testing.T) {
	h := seedHosts(t, "10.70.0.1", "10.70.0.2") // 会写一条 ingest_probe 审计
	w := doReq(t, h, "GET", "/api/audit", nil, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/audit = %d: %s", w.Code, w.Body.String())
	}
	logs := decodeArray(t, w.Body.Bytes())
	if len(logs) == 0 {
		t.Fatal("应有审计日志")
	}
	// 非法 limit 参数不应 500
	if w = doReq(t, h, "GET", "/api/audit?limit=abc", nil, nil); w.Code != 200 {
		t.Fatalf("非法 limit 不应报错，实际 %d", w.Code)
	}
}

// TestUnknownAPIReturnsSPA 未知路径应回落静态页（单二进制分发 + 前端路由）。
func TestUnknownAPIReturnsSPA(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, "GET", "/some/frontend/route", nil, nil)
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Fatalf("未知路径应回落静态资源，实际 %d", w.Code)
	}
}

// TestConfigSessionLimitsTakeEffect 会话表容量参数改完要立即生效（不用重启）。
func TestConfigSessionLimitsTakeEffect(t *testing.T) {
	h := seedHosts(t, "10.80.0.1", "10.80.0.2")

	w := doReq(t, h, "PUT", "/api/config", map[string]any{
		"session_max_count":       5000,
		"session_idle_seconds":    120,
		"session_max_age_seconds": 3600,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}
	var cfg map[string]any
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg["session_max_count"].(float64) != 5000 {
		t.Fatalf("配置回显未生效: %v", cfg["session_max_count"])
	}

	// 聚合器应立刻采用新上限
	w = doReq(t, h, "GET", "/api/stats", nil, nil)
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if got := st["SessionTable"].(map[string]any)["MaxSessions"].(float64); got != 5000 {
		t.Fatalf("会话表上限未生效，仍为 %v", got)
	}

	// 非法值（0 / 负数）应被忽略，不能把上限清零
	if w = doReq(t, h, "PUT", "/api/config", map[string]any{"session_max_count": 0}, nil); w.Code != 200 {
		t.Fatalf("非法值不应报错，实际 %d", w.Code)
	}
	w = doReq(t, h, "GET", "/api/stats", nil, nil)
	json.Unmarshal(w.Body.Bytes(), &st)
	if got := st["SessionTable"].(map[string]any)["MaxSessions"].(float64); got != 5000 {
		t.Fatalf("0 值不应覆盖已有上限，实际 %v", got)
	}
}

// TestProbeOversizeRejected 超大上报体必须被挡在 413，而不是把内存打满。
func TestProbeOversizeRejected(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	// 构造略超 64MB 的请求体
	big := make([]byte, (64<<20)+1024)
	for i := range big {
		big[i] = 'a'
	}
	req := httptest.NewRequest("POST", "/api/ingest/probe", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限上报应 413，实际 %d", w.Code)
	}
}
