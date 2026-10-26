package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"starmap/internal/detect"
	"starmap/internal/discover"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// newDiscoverRouter 构造带主动发现执行器的测试路由。
func newDiscoverRouter(t *testing.T, cfg model.SystemConfig) (http.Handler, *store.Store, *topology.Engine) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("打开内存库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := topology.New(cfg)
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	det := detect.New(st, eng, cfg)
	det.SessionsFunc = agg.Sessions
	det.LearningPeriod = 0
	rvw := review.New(st, eng)
	scanner := probe.New(eng)
	scanner.SetRate(0)
	scanner.NowFunc = time.Now

	runner := &discover.Runner{
		Store: st, Engine: eng, Scanner: scanner,
		Cfg: func() model.SystemConfig { return cfg },
	}
	cfgPtr := &cfg
	h := NewRouter(Deps{
		Store: st, Engine: eng, Detector: det, Reviewer: rvw, Scanner: scanner,
		Cfg: cfgPtr, Aggregator: agg, Discover: runner,
	})
	return h, st, eng
}

func discoverCfg() model.SystemConfig {
	c := testCfg()
	c.DiscoverEnabled = true
	c.DiscoverProfile = probe.ProfileQuick
	c.DiscoverRatePPS = 0
	c.DiscoverConcurrency = 64
	c.DiscoverTimeoutMS = 300
	c.DiscoverFingerprint = true
	c.DiscoverMaxFP = 8
	return c
}

func TestDiscoverPlan(t *testing.T) {
	h, _, _ := newDiscoverRouter(t, discoverCfg())

	w := doReq(t, h, http.MethodGet, "/api/discover/plan", nil, nil)
	var plan struct {
		Profile   string `json:"profile"`
		Label     string `json:"label"`
		PortCount int    `json:"port_count"`
	}
	mustJSON(t, w, &plan)
	if plan.Profile != probe.ProfileQuick || plan.PortCount < 80 {
		t.Errorf("默认档位计划 = %+v", plan)
	}
	if plan.Label == "" {
		t.Error("应给出档位说明")
	}

	w = doReq(t, h, http.MethodGet, "/api/discover/plan?profile=full", nil, nil)
	mustJSON(t, w, &plan)
	if plan.PortCount != 65535 {
		t.Errorf("全端口档位 = %d，期望 65535", plan.PortCount)
	}

	w = doReq(t, h, http.MethodGet, "/api/discover/plan?profile=nope", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法档位应 400，实际 %d", w.Code)
	}
}

func TestDiscoverRunRequiresEnabled(t *testing.T) {
	cfg := discoverCfg()
	cfg.DiscoverEnabled = false
	h, _, _ := newDiscoverRouter(t, cfg)

	w := doReq(t, h, http.MethodPost, "/api/discover/run",
		map[string]any{"target": "127.0.0.1"}, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未启用时应 503，实际 %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "discover_enabled") {
		t.Errorf("错误信息应告诉用户开哪个开关: %s", w.Body.String())
	}
}

func TestDiscoverRunWithoutRunner(t *testing.T) {
	// 插件化装配可能不注入执行器：必须报错而不是 panic
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, http.MethodPost, "/api/discover/run",
		map[string]any{"target": "127.0.0.1"}, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("无执行器时应 503，实际 %d", w.Code)
	}
}

func TestDiscoverRunValidation(t *testing.T) {
	h, _, _ := newDiscoverRouter(t, discoverCfg())

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺少目标", map[string]any{}},
		{"空白目标", map[string]any{"target": "   "}},
		{"非法目标", map[string]any{"target": "not-an-ip"}},
		{"网段过大", map[string]any{"target": "10.0.0.0/8"}},
		{"非法档位", map[string]any{"target": "127.0.0.1", "profile": "turbo"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := doReq(t, h, http.MethodPost, "/api/discover/run", c.body, nil)
			if w.Code != http.StatusBadRequest {
				t.Errorf("应 400，实际 %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDiscoverStatusNotFound(t *testing.T) {
	h, _, _ := newDiscoverRouter(t, discoverCfg())
	w := doReq(t, h, http.MethodGet, "/api/discover/status/discover-999", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("不存在的任务应 404，实际 %d", w.Code)
	}
}

// 端到端：触发 → 轮询 → 完成 → 端口落库（带指纹）。
func TestDiscoverRunEndToEnd(t *testing.T) {
	h, st, _ := newDiscoverRouter(t, discoverCfg())

	w := doReq(t, h, http.MethodPost, "/api/discover/run",
		map[string]any{"target": "127.0.0.1/32", "profile": "quick"}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("应 202，实际 %d body=%s", w.Code, w.Body.String())
	}
	var started struct {
		TaskID string `json:"task_id"`
		Hosts  int    `json:"hosts"`
	}
	// 202 Accepted：任务已接受但未完成，不能用 mustJSON（它要求 200）
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil {
		t.Fatalf("解析启动响应失败: %v body=%s", err, w.Body.String())
	}
	if started.TaskID == "" || started.Hosts != 1 {
		t.Fatalf("启动响应异常: %+v", started)
	}

	deadline := time.Now().Add(60 * time.Second)
	var task discoverTask
	for {
		if time.Now().After(deadline) {
			t.Fatalf("发现任务超时未完成: %+v", task)
		}
		time.Sleep(200 * time.Millisecond)
		w = doReq(t, h, http.MethodGet, "/api/discover/status/"+started.TaskID, nil, nil)
		mustJSON(t, w, &task)
		if task.Status != "running" {
			break
		}
	}
	if task.Status != "done" {
		t.Fatalf("任务状态 = %q err=%q", task.Status, task.Error)
	}
	if task.Total != 1 || task.Done != 1 {
		t.Errorf("进度 = %d/%d", task.Done, task.Total)
	}
	if task.ProfileLabel == "" {
		t.Error("应回显档位说明")
	}

	// 端口表应有记录（本机至少开着一些端口），且来源是 probe
	ports, err := st.ListPorts("127.0.0.1", "")
	if err != nil {
		t.Fatalf("查询端口失败: %v", err)
	}
	if task.OpenPorts > 0 && len(ports) == 0 {
		t.Fatal("发现了开放端口却没有落库")
	}
	for _, p := range ports {
		if p.Source != model.PortSourceProbe {
			t.Errorf("端口 %d 来源 = %q，期望 probe", p.Port, p.Source)
		}
		if p.IP != "127.0.0.1" {
			t.Errorf("端口 IP = %q", p.IP)
		}
	}
	// 活跃主机应进入拓扑
	if len(task.Hosts) > 0 && task.Hosts[0].IP != "127.0.0.1" {
		t.Errorf("结果主机 = %q", task.Hosts[0].IP)
	}
}

// listPorts 必须回指纹字段，否则前端那列永远是空的。
func TestListPortsIncludesFingerprint(t *testing.T) {
	h, st, _ := newDiscoverRouter(t, discoverCfg())
	now := time.Now()
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.0.0.9", IP: "10.0.0.9", Port: 8080, Proto: "tcp",
		Service: "http", State: "open", Source: model.PortSourceProbe,
		Product: "泛微 e-cology", Version: "10.0", Title: "泛微协同办公",
		TLSCN: "oa.example.gov.cn", TLSNames: []string{"oa.example.gov.cn", "10.0.0.9"},
		Favicon: "-1234567", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("写入端口失败: %v", err)
	}

	w := doReq(t, h, http.MethodGet, "/api/ports?ip=10.0.0.9", nil, nil)
	var out []map[string]any
	mustJSON(t, w, &out)
	if len(out) != 1 {
		t.Fatalf("端口数 = %d", len(out))
	}
	p := out[0]
	if p["product"] != "泛微 e-cology" {
		t.Errorf("product = %v", p["product"])
	}
	if p["version"] != "10.0" {
		t.Errorf("version = %v", p["version"])
	}
	if p["title"] != "泛微协同办公" {
		t.Errorf("title = %v", p["title"])
	}
	if p["tls_cn"] != "oa.example.gov.cn" {
		t.Errorf("tls_cn = %v", p["tls_cn"])
	}
	names, ok := p["tls_names"].([]any)
	if !ok || len(names) != 2 {
		t.Errorf("tls_names = %v", p["tls_names"])
	}
	if p["favicon_hash"] != "-1234567" {
		t.Errorf("favicon_hash = %v", p["favicon_hash"])
	}
}

func TestPutConfigDiscover(t *testing.T) {
	h, _, _ := newDiscoverRouter(t, discoverCfg())

	w := doReq(t, h, http.MethodPut, "/api/config", map[string]any{
		"discover_enabled":          true,
		"discover_profile":          "standard",
		"discover_rate_pps":         200,
		"discover_concurrency":      128,
		"discover_timeout_ms":       600,
		"discover_fingerprint":      false,
		"discover_max_fingerprints": 16,
		"discover_window":           "22:00-06:00",
		"discover_sec":              3600,
		"discover_cidrs":            []string{"10.10.1.0/24", "10.10.2.0/24"},
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("保存配置失败: %d %s", w.Code, w.Body.String())
	}
	var cfg map[string]any
	mustJSON(t, w, &cfg)
	if cfg["discover_profile"] != "standard" {
		t.Errorf("profile 未生效: %v", cfg["discover_profile"])
	}
	if cfg["discover_rate_pps"].(float64) != 200 {
		t.Errorf("rate 未生效: %v", cfg["discover_rate_pps"])
	}
	if cfg["discover_fingerprint"].(bool) {
		t.Error("fingerprint 应为 false")
	}
	if cfg["discover_window"] != "22:00-06:00" {
		t.Errorf("window 未生效: %v", cfg["discover_window"])
	}
	cidrs, _ := cfg["discover_cidrs"].([]any)
	if len(cidrs) != 2 {
		t.Errorf("cidrs = %v", cfg["discover_cidrs"])
	}

	// 非法时间窗口必须当场拒绝：写进去只会让周期扫描静默不执行
	w = doReq(t, h, http.MethodPut, "/api/config",
		map[string]any{"discover_window": "晚上十点"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法窗口应 400，实际 %d", w.Code)
	}
	// 清空窗口 = 全天，允许
	w = doReq(t, h, http.MethodPut, "/api/config", map[string]any{"discover_window": ""}, nil)
	if w.Code != http.StatusOK {
		t.Errorf("清空窗口应允许，实际 %d", w.Code)
	}
}

// 限速配置改动必须立即作用于扫描器（不然"调低速率"要等重启才生效）。
func TestPutConfigDiscoverAppliesRate(t *testing.T) {
	h, _, _ := newDiscoverRouter(t, discoverCfg())
	// 用一次扫描的耗时不便断言，这里只验证接口不报错且值回显
	w := doReq(t, h, http.MethodPut, "/api/config", map[string]any{"discover_rate_pps": 50}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("保存失败: %d", w.Code)
	}
	var cfg map[string]any
	mustJSON(t, w, &cfg)
	if cfg["discover_rate_pps"].(float64) != 50 {
		t.Errorf("速率未生效: %v", cfg["discover_rate_pps"])
	}
}
