package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// gatherValue 从 Registry 里按名字取出唯一的指标当前值。
//
// 直接用 Gather + 取第一个 metric：本包的 gauge/counter 都是无标签标量，
// 用 testutil.ToFloat64 反而要先构造一个 Collector，绕远路。
func gatherValue(t *testing.T, m *Metrics, name string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		if len(f.GetMetric()) == 0 {
			t.Fatalf("指标 %s 没有样本", name)
		}
		mt := f.GetMetric()[0]
		if mt.GetGauge() != nil {
			return mt.GetGauge().GetValue()
		}
		if mt.GetCounter() != nil {
			return mt.GetCounter().GetValue()
		}
	}
	t.Fatalf("指标 %s 不存在", name)
	return 0
}

func gatherNames(m *Metrics) map[string]bool {
	families, err := m.Registry().Gather()
	if err != nil {
		return nil
	}
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	return names
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	return rec.Body.String()
}

// TestGaugeFuncsReflectLiveState 状态类指标必须现读现算：
// 改闭包状态后抓取值应立刻变化，不需要任何"记得推送"的埋点。
func TestGaugeFuncsReflectLiveState(t *testing.T) {
	nodes, edges := 12, 30
	sessions, dropped := 3, int64(7)
	m := New(Providers{
		TopologyNodes:   func() int { return nodes },
		TopologyEdges:   func() int { return edges },
		SessionsActive:  func() int { return sessions },
		SessionsDropped: func() int64 { return dropped },
	})

	if got := gatherValue(t, m, "starmap_topology_nodes"); got != 12 {
		t.Fatalf("starmap_topology_nodes = %v, want 12", got)
	}

	nodes, edges, sessions, dropped = 100, 200, 5, 9
	for name, want := range map[string]float64{
		"starmap_topology_nodes":         100,
		"starmap_topology_edges":         200,
		"starmap_sessions_active":        5,
		"starmap_sessions_dropped_total": 9,
	} {
		if got := gatherValue(t, m, name); got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}

func TestNilProvidersAreSkipped(t *testing.T) {
	m := New(Providers{TopologyNodes: func() int { return 1 }})
	names := gatherNames(m)
	if names == nil {
		t.Fatal("Gather 失败")
	}
	if !names["starmap_topology_nodes"] {
		t.Fatal("应导出 starmap_topology_nodes")
	}
	// 没给读取函数的指标不应出现，否则看板上是一堆永远为 0 的死指标
	for _, unexpected := range []string{"starmap_events_pending", "starmap_sessions_dropped_total"} {
		if names[unexpected] {
			t.Fatalf("nil provider 不应注册 %s", unexpected)
		}
	}
}

func TestHandlerServesPrometheusText(t *testing.T) {
	m := New(Providers{TopologyNodes: func() int { return 3 }})
	body := scrape(t, m)
	for _, want := range []string{"starmap_topology_nodes", "go_goroutines", "process_cpu_seconds_total"} {
		if !strings.Contains(body, want) {
			t.Fatalf("响应缺少 %s", want)
		}
	}
}

// TestMiddlewareLabelsNotExploded 路由模板作 label：/api/nodes/1 与 /api/nodes/2
// 必须归并到同一条时间序列，否则 Prometheus 会被高基数标签打爆。
func TestMiddlewareLabelsNotExploded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New(Providers{})
	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/api/nodes/:id", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for _, p := range []string{"/api/nodes/1", "/api/nodes/2", "/api/nodes/999"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	body := scrape(t, m)

	if strings.Contains(body, `route="/api/nodes/1"`) {
		t.Fatal("label 用了原始 URL，会造成标签爆炸")
	}
	if !strings.Contains(body, `route="/api/nodes/:id"`) {
		t.Fatalf("未使用路由模板作 label:\n%s", firstLines(body, 40))
	}
	if !strings.Contains(body, `starmap_http_requests_total{method="GET",route="/api/nodes/:id",status="200"} 3`) {
		t.Fatalf("请求计数不正确:\n%s", firstLines(body, 40))
	}
}

// TestMiddlewareCountsUnmatched 未匹配路由用固定 label，
// 不能让 404 扫描器每个 URL 造出一条新时间序列。
func TestMiddlewareCountsUnmatched(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New(Providers{})
	r := gin.New()
	r.Use(m.Middleware())
	r.NoRoute(func(c *gin.Context) { c.String(http.StatusNotFound, "nope") })

	for i := 0; i < 5; i++ {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/random/path/"+string(rune('a'+i)), nil))
	}
	body := scrape(t, m)
	if !strings.Contains(body, `route="unmatched"`) {
		t.Fatalf("未匹配路由应归到 route=\"unmatched\":\n%s", firstLines(body, 40))
	}
	if got := strings.Count(body, `starmap_http_requests_total{method="GET",route="unmatched",status="404"}`); got != 1 {
		t.Fatalf("不同 URL 应合并为一条序列，实际 %d 条", got)
	}
}

func TestBusinessCounters(t *testing.T) {
	m := New(Providers{})
	m.IngestPacket("pcap", 1024)
	m.IngestPacket("capture", 0)
	m.DetectionRun(150*time.Millisecond, 2)
	m.ProbeReport("ok")
	m.ProbeReport("unauthorized")

	body := scrape(t, m)
	for _, want := range []string{
		`starmap_ingest_packets_total{source="pcap"} 1`,
		`starmap_ingest_packets_total{source="capture"} 1`,
		"starmap_ingest_bytes_total 1024",
		"starmap_detection_runs_total 1",
		"starmap_detection_events_total 2",
		`starmap_probe_reports_total{result="ok"} 1`,
		`starmap_probe_reports_total{result="unauthorized"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("缺少指标行 %q", want)
		}
	}
}

// TestIndependentRegistry 每个实例独立 Registry：测试里反复 New 不能 panic（重复注册）。
func TestIndependentRegistry(t *testing.T) {
	a := New(Providers{TopologyNodes: func() int { return 1 }})
	b := New(Providers{TopologyNodes: func() int { return 2 }})
	if gatherValue(t, a, "starmap_topology_nodes") != 1 {
		t.Fatal("实例 a 数值被污染")
	}
	if gatherValue(t, b, "starmap_topology_nodes") != 2 {
		t.Fatal("实例 b 数值被污染")
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
