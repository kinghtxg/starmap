package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// 这一组用例锁的是「探针重发不会把流量放大」。
//
// 现场症状：真实库里 25 分钟的一条 HTTPS 长连接被记成 850MB，整库 28GB，
// 而同一时刻本机网卡真实吞吐只有 0.1MB/s。根因是探针每 5 秒把会话的累计值
// 整条重发一遍，服务端按"新增报文"把它累加了一次又一次。
// 字节数是拓扑、端口、风险评分共用的分母，它错了，界面上每个数字都不可信。

func postFlows(t *testing.T, h http.Handler, flows ...map[string]any) {
	t.Helper()
	body := map[string]any{
		"probe_id": "probe-bytes",
		"ts":       base.Format(time.RFC3339),
		"flows":    flows,
	}
	if w := doReq(t, h, "POST", "/api/ingest/probe", body, nil); w.Code != http.StatusOK {
		t.Fatalf("上报失败 %d: %s", w.Code, w.Body.String())
	}
}

func flowSnapshot(up, down int64, first time.Time) map[string]any {
	return map[string]any{
		"src_ip": "10.20.30.40", "dst_ip": "203.0.113.9",
		"src_port": 51000, "dst_port": 443, "proto": "tcp",
		"mac":      "02:00:00:00:00:ee",
		"bytes_up": up, "bytes_down": down, "packets": 12,
		"first_seen": first.Format(time.RFC3339),
		"last_seen":  first.Add(3 * time.Minute).Format(time.RFC3339),
		"sni":        "example.com",
	}
}

func topoStats(t *testing.T, h http.Handler) (int64, map[string]any) {
	t.Helper()
	w := doReq(t, h, "GET", "/api/topology", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("取拓扑失败 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Stats map[string]any   `json:"Stats"`
		Nodes []map[string]any `json:"Nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析拓扑失败: %v", err)
	}
	total, _ := resp.Stats["TotalBytes"].(float64)
	host := findNode(t, h, func(n map[string]any) bool {
		for _, ip := range nodeIPs(n) {
			if ip == "10.20.30.40" {
				return true
			}
		}
		return false
	})
	return int64(total), host
}

// TestProbeResendDoesNotInflateBytes 同一条会话上报 6 次（累计值递增），
// 总字节必须等于最终累计值，而不是 6 次之和。
func TestProbeResendDoesNotInflateBytes(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	first := base
	for _, up := range []int64{1500, 3000, 4500, 6000, 7500, 9000} {
		postFlows(t, h, flowSnapshot(up, 500, first))
	}
	total, host := topoStats(t, h)
	if total != 9500 {
		t.Fatalf("上报 6 次累计到 9000+500，总字节应为 9500，实际 %d（放大 %.1f 倍）",
			total, float64(total)/9500)
	}
	// 端口明细走的是同一条增量路径，必须一起对上，否则"点开主机看端口"看到的
	// 是放大后的数字，比没有更糟。
	out := portList(t, host, "OutPorts")
	if n, ok := out[443]; !ok || n != 1 {
		t.Fatalf("出向 443 应只有 1 条会话，实际 %v", out)
	}
	// 端口字节是整条会话的上下行之和（9000+500），与边的口径一致。
	if b := portBytes(host, "OutPorts", 443); b != 9500 {
		t.Fatalf("出向 443 的字节应为 9500，实际 %d", b)
	}
}

// TestProbeDuplicateReportIsIdempotent 原样重发（累计值不变）不能产生任何增量。
func TestProbeDuplicateReportIsIdempotent(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	f := flowSnapshot(4000, 1000, base)
	for i := 0; i < 10; i++ {
		postFlows(t, h, f)
	}
	total, _ := topoStats(t, h)
	if total != 5000 {
		t.Fatalf("同一份快照重发 10 次应为 5000，实际 %d", total)
	}
}

// TestProbeTwoDirectionsOneSession 一条流只代表一条会话（上下行分开计），
// 不能因为两个方向都被统计就多算一条会话。
func TestProbeTwoDirectionsOneSession(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	postFlows(t, h, flowSnapshot(100, 900, base))
	_, host := topoStats(t, h)
	out := portList(t, host, "OutPorts")
	if n := out[443]; n != 1 {
		t.Fatalf("出向 443 的会话数应为 1，实际 %d", n)
	}
	if in := portList(t, host, "InPorts"); len(in) != 0 {
		t.Fatalf("客户端不该有入向端口，实际 %v", in)
	}
}

// portBytes 取某个节点的端口字节数，用于断言端口统计没被放大。
func portBytes(n map[string]any, field string, port int) int64 {
	raw, _ := n[field].([]any)
	for _, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if p, _ := m["port"].(float64); int(p) == port {
			b, _ := m["bytes"].(float64)
			return int64(b)
		}
	}
	return -1
}
