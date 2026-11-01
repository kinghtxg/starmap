package e2e

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// get 取一个返回对象的接口（e.list 只处理数组）。
func (e *env) get(path string) map[string]any {
	e.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 200 {
		e.t.Fatalf("GET %s → %d: %s", path, w.Code, w.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		e.t.Fatalf("GET %s 响应非 JSON 对象: %s", path, w.Body.String())
	}
	return m
}

// IP 冲突的端到端链路：上报 → 引擎 → 规则 → 接口。
//
// 单测里可以直连 evalIPConflict，但那不证明 HTTP 那条路、去重那条路、事件
// 落库那条路都是通的——这几处恰恰最容易出问题：事件类型没登记、去重把自己
// 压掉、字段名对不上、检测器的 NodeEffect 又往节点上补一个同义标签。
// 这个用例全部走真实接口，只保留"手动跑一轮评估"这一个捷径（异步 kick 要等 5 秒）。
func TestIPConflictEndToEnd(t *testing.T) {
	e := newEnv(t)
	peer, target := "10.20.0.9", "10.20.0.30"
	macA, macB := "02:00:00:00:00:aa", "02:00:00:00:00:bb"
	now := time.Now().UTC()

	post := func(flows []map[string]any) {
		e.t.Helper()
		code, body := e.do("POST", "/api/ingest/probe", map[string]any{
			"probe_id": "p-e2e", "location": "测试机房",
			"sent_at": now.Format(time.RFC3339),
			"flows":   flows,
		})
		if code != 200 {
			e.t.Fatalf("上报失败 %d: %v", code, body)
		}
	}
	flow := func(src, dst, mac string, sport, dport int) map[string]any {
		return map[string]any{
			"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
			"proto": "tcp", "mac": mac, "bytes_up": 6000, "bytes_down": 1000,
			"packets": 40, "first_seen": now.Format(time.RFC3339), "last_seen": now.Format(time.RFC3339),
		}
	}

	// 目的端先出现（只有 IP，没有 MAC——跨三层就是如此），随后两台机器各发包
	post([]map[string]any{flow(peer, target, "02:00:00:00:00:09", 40001, 80)})
	post([]map[string]any{flow(target, peer, macA, 40002, 80)})
	post([]map[string]any{flow(target, peer, macB, 40003, 80)})

	if _, err := e.det.Evaluate(); err != nil {
		t.Fatalf("评估失败: %v", err)
	}

	evs := e.list("/api/events?type=ip_conflict")
	if len(evs) != 1 {
		t.Fatalf("应产出 1 条 ip_conflict 事件，实际 %d: %v", len(evs), evs)
	}
	ev := evs[0]
	if ev["Level"] != "mid" {
		t.Fatalf("级别应为 mid（地址冲突多是事故，ARP 欺骗才定性），实际 %v", ev["Level"])
	}
	evidence, _ := ev["Evidence"].(map[string]any)
	if evidence["ip"] != target || evidence["count"] != "2" {
		t.Fatalf("证据不全: %v", evidence)
	}

	topo := e.get("/api/topology")
	owners := 0
	for _, n := range topo["Nodes"].([]any) {
		node := n.(map[string]any)
		ips, _ := node["IPs"].([]any)
		hit := false
		for _, ip := range ips {
			if ip == target {
				hit = true
			}
		}
		if !hit {
			continue
		}
		owners++
		labels, _ := node["Labels"].([]any)
		marked := false
		for _, l := range labels {
			if l == "ip_conflict" {
				marked = true
			}
		}
		if !marked {
			t.Fatalf("节点 %v 没打 ip_conflict 标记（图上不会刺眼）: %v", node["NodeKey"], labels)
		}
	}
	if owners != 2 {
		t.Fatalf("冲突地址上应有 2 个节点（两台机器抢一个 IP），实际 %d", owners)
	}
}
