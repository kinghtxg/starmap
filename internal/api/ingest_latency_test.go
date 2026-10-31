// 上报路径的规模门禁（V1.5.2 P0）。
//
// 背景：ingestProbe 曾在请求线程里同步跑一轮全量检测（evaluateAsync）。
// 于是「一次探针上报的耗时」= 「一轮全量检测的耗时」，实测：
//
//	1000 会话 → 13 秒，3000 会话 → 42 秒，且延迟随会话数线性上涨。
//
// 真实环境里探针 5 秒上报一次，等于每批上报都在等上一轮检测跑完，
// 数据接入会被自己的检测堵死（而界面上只表现为"探针离线"）。
//
// 现在上报只同步做「写入 + 拓扑同步」，检测交给后台评估器（Kick 合并触发）。
// 本文件守住两件事：上报延迟不随规模劣化；响应明确声明检测是异步的。
package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// decodeObject 把 JSON 对象解成 map（本文件自用，避免和其他用例抢名字）。
func decodeObject(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("响应不是 JSON 对象: %s", string(b))
	}
	return out
}

// bulkFlows 造 n 条互不相同的 flows（同一条上报里），用于快速把状态堆起来。
func bulkFlows(n, startID int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		id := startID + i
		out = append(out, map[string]any{
			"src_ip":   fmt.Sprintf("10.30.%d.%d", (id>>8)&0xff, id&0xff),
			"dst_ip":   "172.16.9.9",
			"src_port": 20000 + id%40000,
			"dst_port": 443,
			"proto":    "tcp",
			"mac":      fmt.Sprintf("02:0a:%02x:%02x:%02x:01", (id>>16)&0xff, (id>>8)&0xff, id&0xff),
			"bytes_up": 1000 + id, "bytes_down": 2000 + id, "packets": 10,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(time.Minute).Format(time.RFC3339),
		})
	}
	return out
}

// TestProbeIngestLatencyDoesNotGrowWithState 上报延迟不得随会话规模线性增长。
func TestProbeIngestLatencyDoesNotGrowWithState(t *testing.T) {
	// -race 下整体慢 5~10 倍，2 秒的上界必然误报——跳过的是"耗时预算"这一条断言，
	// 功能断言（状态码、eval_async）在别的用例里照跑。
	if raceEnabled {
		t.Skip("-race 下执行速度不可比，跳过耗时预算断言")
	}
	h, _ := newTestRouter(t, testCfg())

	// ① 先把状态堆到 3000 个会话（旧实现每加一批，下一批就更慢）
	w := doReq(t, h, "POST", "/api/ingest/probe", map[string]any{
		"probe_id": "bulk", "sent_at": base.Format(time.RFC3339),
		"flows": bulkFlows(3000, 1),
	}, nil)
	if w.Code != 200 {
		t.Fatalf("批量播种失败 %d: %s", w.Code, w.Body.String())
	}

	// ② 再上报一小批，测量耗时
	start := time.Now()
	w = doReq(t, h, "POST", "/api/ingest/probe", map[string]any{
		"probe_id": "tiny", "sent_at": base.Format(time.RFC3339),
		"flows": bulkFlows(50, 90001),
	}, nil)
	elapsed := time.Since(start)
	if w.Code != 200 {
		t.Fatalf("上报失败 %d: %s", w.Code, w.Body.String())
	}
	// 旧实现在这个规模下要 40 秒以上（同步跑一轮全量检测）。
	// 2 秒的上界足够宽，能挡住"把检测塞回请求线程"的回归，又不会在慢机器上误报。
	if elapsed > 2*time.Second {
		t.Fatalf("3000 会话状态下一次上报耗时 %v，检测很可能又被塞回了请求路径", elapsed)
	}
}

// TestProbeIngestDeclaresAsyncEvaluation 响应必须明确声明检测已异步化，
// 否则调用方（探针 / 前端）会继续把 new_events 当成"本次上报产出的事件数"。
func TestProbeIngestDeclaresAsyncEvaluation(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, "POST", "/api/ingest/probe", map[string]any{
		"probe_id": "p-async", "sent_at": base.Format(time.RFC3339),
		"flows": bulkFlows(5, 1),
	}, nil)
	if w.Code != 200 {
		t.Fatalf("上报失败 %d: %s", w.Code, w.Body.String())
	}
	m := decodeObject(t, w.Body.Bytes())
	if v, ok := m["eval_async"]; !ok || v != true {
		t.Fatalf("响应应声明 eval_async=true，实际 %v", m)
	}
	if v, ok := m["new_events"]; !ok || v.(float64) != 0 {
		t.Fatalf("异步语义下 new_events 应恒为 0，实际 %v", m["new_events"])
	}
}
