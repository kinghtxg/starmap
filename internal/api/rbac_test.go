package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"testing"

	"starmap/internal/auth"
	"starmap/internal/metrics"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// newRouterWith 构造带认证/指标的路由，用于验证路由级 RBAC 与 /metrics 鉴权。
//
// 这里注入的是"已认证"的中间件：直接往 gin.Context 写角色，
// 跳过 Cookie 解析——本用例要验证的是**路由分组是否正确**，
// 会话签发/校验由 internal/auth 自己的用例覆盖。
func newRouterWith(t *testing.T, cfg model.SystemConfig, role string, withMetrics bool) http.Handler {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := topology.New(cfg)
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	rvw := review.New(st, eng)
	scanner := probe.New(eng)

	var met *metrics.Metrics
	if withMetrics {
		met = metrics.New(metrics.Providers{
			TopologyNodes:  func() int { return 1 },
			SessionsActive: func() int { return 0 },
		})
	}
	return NewRouter(Deps{
		Store: st, Engine: eng, Detector: nil, Reviewer: rvw, Scanner: scanner,
		Cfg: &cfg, Aggregator: agg, Metrics: met,
		// 模拟"已认证且角色为 role"的请求上下文；生产代码不带这个中间件。
		Middleware: []gin.HandlerFunc{func(c *gin.Context) {
			if role != "" {
				c.Set(auth.CtxRole, role)
			}
		}},
	})
}

func TestRouteRBACMatrix(t *testing.T) {
	cfg := testCfg()
	type probeReq struct {
		method, path string
		need         string // viewer | operator | admin
	}
	cases := []probeReq{
		{http.MethodGet, "/api/topology", auth.RoleViewer},
		{http.MethodGet, "/api/events", auth.RoleViewer},
		{http.MethodGet, "/api/assets", auth.RoleViewer},
		{http.MethodGet, "/api/config", auth.RoleViewer},
		{http.MethodGet, "/api/audit", auth.RoleViewer},
		{http.MethodGet, "/api/ledger/diff", auth.RoleViewer},
		{http.MethodPost, "/api/events/1/review", auth.RoleOperator},
		{http.MethodPost, "/api/whitelist", auth.RoleOperator},
		{http.MethodPost, "/api/capture/stop", auth.RoleOperator},
		{http.MethodPut, "/api/config", auth.RoleAdmin},
		{http.MethodDelete, "/api/whitelist/1", auth.RoleAdmin},
		{http.MethodDelete, "/api/assets/k", auth.RoleAdmin},
		{http.MethodDelete, "/api/ledger", auth.RoleAdmin},
	}
	roles := []string{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin}
	rank := map[string]int{auth.RoleViewer: 1, auth.RoleOperator: 2, auth.RoleAdmin: 3}

	for _, c := range cases {
		for _, role := range roles {
			router := newRouterWith(t, cfg, role, false)
			rec := doReq(t, router, c.method, c.path, []byte("{}"), nil)
			allowed := rank[role] >= rank[c.need]
			if allowed {
				// 放行不一定 2xx（可能 400/404），但绝不能是 403
				if rec.Code == http.StatusForbidden {
					t.Fatalf("%s %s 被 %s 角色访问应放行，实际 403", c.method, c.path, role)
				}
			} else {
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s %s 被 %s 角色访问应 403，实际 %d（要求 %s）",
						c.method, c.path, role, rec.Code, c.need)
				}
			}
		}
	}
}

func TestMetricsRequiresAdminOrToken(t *testing.T) {
	cfg := testCfg()

	// 1) 配置了 metrics_token → 必须带对头
	cfgTok := cfg
	cfgTok.MetricsToken = "s3cr3t"
	h := newRouterWith(t, cfgTok, auth.RoleViewer, true)
	if rec := doReq(t, h, http.MethodGet, "/metrics", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("缺少 token 应 401，得到 %d", rec.Code)
	}
	if rec := doReq(t, h, http.MethodGet, "/metrics", nil, map[string]string{"X-Metrics-Token": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误 token 应 401，得到 %d", rec.Code)
	}
	if rec := doReq(t, h, http.MethodGet, "/metrics", nil, map[string]string{"X-Metrics-Token": "s3cr3t"}); rec.Code != http.StatusOK {
		t.Fatalf("正确 token 应 200，得到 %d", rec.Code)
	}
	if !strings.Contains(doReq(t, h, http.MethodGet, "/metrics", nil, map[string]string{"X-Metrics-Token": "s3cr3t"}).Body.String(), "starmap_topology_nodes") {
		t.Fatal("响应缺少指标内容")
	}

	// 2) 未配置 token → 只放行 admin 会话
	hViewer := newRouterWith(t, cfg, auth.RoleViewer, true)
	if rec := doReq(t, hViewer, http.MethodGet, "/metrics", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 读 /metrics 应 403，得到 %d", rec.Code)
	}
	hAdmin := newRouterWith(t, cfg, auth.RoleAdmin, true)
	if rec := doReq(t, hAdmin, http.MethodGet, "/metrics", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin 读 /metrics 应 200，得到 %d", rec.Code)
	}

	// 3) 未接指标集合 → /metrics 不注册（404，不会留下一个空壳端点）
	hNo := newRouterWith(t, cfg, auth.RoleAdmin, false)
	if rec := doReq(t, hNo, http.MethodGet, "/metrics", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("未启用指标时应 404，得到 %d", rec.Code)
	}
}

// TestMetricsTokenNotEchoed 令牌不能经 GET /api/config 回显明文（只回显是否已设置）。
func TestMetricsTokenNotEchoed(t *testing.T) {
	cfg := testCfg()
	cfg.MetricsToken = "topsecret-token"
	h := newRouterWith(t, cfg, auth.RoleAdmin, true)
	rec := doReq(t, h, http.MethodGet, "/api/config", nil, nil)
	body := rec.Body.String()
	if strings.Contains(body, "topsecret-token") {
		t.Fatalf("配置接口回显了明文令牌: %s", body)
	}
	if !strings.Contains(body, `"metrics_token_set":true`) {
		t.Fatalf("应回显 metrics_token_set=true: %s", body)
	}
}
