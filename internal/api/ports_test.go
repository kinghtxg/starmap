package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// 拓扑节点必须带"它连了对方什么端口"。这是详情面板与悬浮卡的唯一数据来源：
// 少了这两个字段，用户点开一台机器只能看到一个 IP——知道他连了谁，
// 却不知道连的是 443（上网）还是 7000（隧道），而后者才是判断依据。

// portList 把节点 JSON 里的端口数组取成 map[端口]会话数，方便断言。
func portList(t *testing.T, n map[string]any, field string) map[int]int {
	t.Helper()
	out := map[int]int{}
	raw, _ := n[field].([]any)
	for _, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s 的元素不是对象: %#v", field, v)
		}
		p, _ := m["port"].(float64)
		if p == 0 {
			t.Fatalf("%s 里的端口字段缺失或为 0: %#v（JSON tag 写错时会静默变成空）", field, m)
		}
		ses, _ := m["sessions"].(float64)
		out[int(p)] = int(ses)
	}
	return out
}

func TestTopologyExposesPortUse(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	seedTopology(t, h) // 10.1.1.5 → 203.0.113.60:7000

	host := findNode(t, h, func(n map[string]any) bool {
		for _, ip := range nodeIPs(n) {
			if ip == "10.1.1.5" {
				return true
			}
		}
		return false
	})
	out := portList(t, host, "OutPorts")
	if n, ok := out[7000]; !ok || n < 1 {
		t.Fatalf("内网主机应记录它连出去的对方端口 7000，实际 %v", out)
	}
	if in := portList(t, host, "InPorts"); len(in) != 0 {
		t.Fatalf("客户端不该有入向端口（那是「别人连它」），实际 %v", in)
	}

	// 公网 /24 聚合节点要能看到"被访问的端口"——它是判断"正常上网 vs 外联隧道"
	// 最直接的一手证据，比归属地更具体。
	ext := findNode(t, h, func(n map[string]any) bool {
		for _, ip := range nodeIPs(n) {
			if ip == "203.0.113.0/24" {
				return true
			}
		}
		return false
	})
	in := portList(t, ext, "InPorts")
	if _, ok := in[7000]; !ok {
		t.Fatalf("公网节点应记录被访问的端口 7000，实际 %v", in)
	}
}

// 单点详情接口必须给出同样的端口数据：详情面板走的是 /api/nodes/{id}，
// 与快照不是同一条取数路径，两边不一致的话"图上悬停有、点进去没有"。
func TestNodeDetailExposesPortUse(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	seedTopology(t, h)

	n := findNode(t, h, func(n map[string]any) bool {
		for _, ip := range nodeIPs(n) {
			if ip == "10.1.1.5" {
				return true
			}
		}
		return false
	})
	id, _ := n["NumID"].(float64)
	if id == 0 {
		t.Fatalf("拿不到节点数字 ID: %#v", n)
	}

	w := doReq(t, h, "GET", "/api/nodes/"+strconv.Itoa(int(id)), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/nodes/%d = %d", int(id), w.Code)
	}
	var resp struct {
		Node map[string]any `json:"Node"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析节点详情失败: %v", err)
	}
	if _, ok := portList(t, resp.Node, "OutPorts")[7000]; !ok {
		t.Fatalf("详情接口应同样给出 OutPorts，实际 %#v", resp.Node["OutPorts"])
	}
}
