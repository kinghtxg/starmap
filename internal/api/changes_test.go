package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"starmap/internal/model"
)

func seedPort(t *testing.T, srv *Server, ip string, port int, first, last time.Time) {
	t.Helper()
	if err := srv.d.Store.UpsertPort(&model.PortRecord{
		NodeKey: "ip:" + ip, IP: ip, Port: port, Proto: "tcp",
		Service: "http", State: "open", Source: "probe",
		FirstSeen: first, LastSeen: last,
	}); err != nil {
		t.Fatalf("写端口失败: %v", err)
	}
}

// TestChangesAPI 变更接口的三块内容：新增、消失、汇总。
func TestChangesAPI(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	now := time.Now()
	seedPort(t, srv, "10.0.0.5", 22, now.AddDate(0, 0, -30), now)                      // 一直在
	seedPort(t, srv, "10.0.0.6", 8080, now.AddDate(0, 0, -1), now)                     // 新增
	seedPort(t, srv, "10.0.0.7", 3389, now.AddDate(0, 0, -30), now.AddDate(0, 0, -20)) // 消失
	seedPort(t, srv, "10.0.0.6", 9090, now.AddDate(0, 0, -1), now)                     // 同一台主机的第二个新端口

	w := doReq(t, h, http.MethodGet, "/api/changes?days=7", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Days  int         `json:"days"`
		Added changeGroup `json:"added"`
		Gone  changeGroup `json:"gone"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resp.Days != 7 {
		t.Fatalf("days 未回显: %d", resp.Days)
	}
	if resp.Added.Total != 2 || len(resp.Added.Items) != 2 {
		t.Fatalf("新增不符: total=%d items=%d", resp.Added.Total, len(resp.Added.Items))
	}
	// 两个新端口来自同一台主机 → 主机数必须是 1，不是 2。
	// 这个数字决定了处置方式：1 台机器新上业务 vs 全网推新客户端。
	if resp.Added.Hosts != 1 {
		t.Fatalf("去重主机数应为 1，实际 %d", resp.Added.Hosts)
	}
	if resp.Gone.Total != 1 || resp.Gone.Items[0].Port != 3389 {
		t.Fatalf("消失不符: %#v", resp.Gone)
	}
	if resp.Gone.Hosts != 1 {
		t.Fatalf("消失主机数应为 1，实际 %d", resp.Gone.Hosts)
	}
}

// TestChangesEmptyShape 空数据时 items 必须是 []，不能是 null。
func TestChangesEmptyShape(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodGet, "/api/changes", nil, nil)
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, k := range []string{"added", "gone"} {
		var g struct {
			Items json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(resp[k], &g); err != nil {
			t.Fatalf("%s 解析失败: %v", k, err)
		}
		if string(g.Items) != "[]" {
			t.Fatalf("%s.items 应是 []，实际 %s", k, string(g.Items))
		}
	}
}

// TestChangesClampsDays 超大 / 非法 days 被夹取，不会退化成全表查询。
func TestChangesClampsDays(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	for _, q := range []string{"?days=99999", "?days=-5", "?days=abc", "?days=0"} {
		w := doReq(t, h, http.MethodGet, "/api/changes"+q, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 状态码 %d", q, w.Code)
		}
		var resp struct {
			Days int `json:"days"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Days < 1 || resp.Days > changeMaxDays {
			t.Fatalf("%s 未被夹取: days=%d", q, resp.Days)
		}
	}
}

// TestTrendAPI 趋势接口：长度、日期连续性、缓存标记。
func TestTrendAPI(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	now := time.Now()
	seedPort(t, srv, "10.0.1.1", 80, now.Add(-time.Hour), now)

	w := doReq(t, h, http.MethodGet, "/api/trend?days=7", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Days   int                `json:"days"`
		Points []model.TrendPoint `json:"points"`
		Cached bool               `json:"cached"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resp.Days != 7 || len(resp.Points) != 7 {
		t.Fatalf("序列长度不符: days=%d len=%d", resp.Days, len(resp.Points))
	}
	if resp.Cached {
		t.Fatal("首次请求不该标记为缓存")
	}
	today := now.Format("2006-01-02")
	if resp.Points[6].Date != today {
		t.Fatalf("最后一天应是今天 %s，实际 %s", today, resp.Points[6].Date)
	}
	if resp.Points[6].Ports != 1 {
		t.Fatalf("今天的端口数应为 1，实际 %d", resp.Points[6].Ports)
	}

	// 第二次同参数应命中缓存（省掉一次三表扫描）
	w = doReq(t, h, http.MethodGet, "/api/trend?days=7", nil, nil)
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Cached {
		t.Fatal("同参数二次请求应命中缓存")
	}

	// 换天数必须重算，不能把 7 天的结果当 30 天返回
	w = doReq(t, h, http.MethodGet, "/api/trend?days=30", nil, nil)
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Days != 30 || len(resp.Points) != 30 {
		t.Fatalf("换天数后未重算: days=%d len=%d", resp.Days, len(resp.Points))
	}
	if resp.Cached {
		t.Fatal("不同参数不该复用缓存")
	}
}
