package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"starmap/internal/config"
	"starmap/internal/detect"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// testDeps 组装一套最小的 Deps（与 newTestRouter 同构，但把 Store 交出去复用）。
func testDeps(cfg model.SystemConfig, st *store.Store) Deps {
	eng := topology.New(cfg)
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	det := detect.New(st, eng, cfg)
	det.SessionsFunc = agg.Sessions
	det.LearningPeriod = 0
	return Deps{
		Store: st, Engine: eng, Detector: det, Reviewer: review.New(st, eng),
		Scanner: probe.New(eng), Cfg: config.NewBox(cfg), Aggregator: agg,
	}
}

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// newTaskRouter 构造一个带任务账的路由，并交回 Server 以便摆出白盒状态。
func newTaskRouter(t *testing.T) (http.Handler, *store.Store, *Server) {
	t.Helper()
	cfg := testCfg()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h, s := newRouterWithServer(testDeps(cfg, st))
	return h, st, s
}

// seedTask 往任务账里塞一条历史任务。
func seedTask(t *testing.T, st *store.Store, id, status string, at time.Time) {
	t.Helper()
	if err := st.StartDiscoverTask(model.DiscoverTask{
		ID: id, Targets: []string{"10.0.0.0/24"}, Profile: "common",
		ProfileLabel: "常用端口", Status: status, Total: 254, StartedAt: at,
		CreatedBy: "admin",
	}); err != nil {
		t.Fatalf("预置任务失败: %v", err)
	}
}

// TestListTasksEmpty 空库返回空数组而不是 null。
//
// null 会让前端 `list.map(...)` 直接抛，整页白屏；空数组才是"没有任务"。
func TestListTasksEmpty(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodGet, "/api/tasks", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	if body := strings.TrimSpace(w.Body.String()); body != "[]" {
		t.Fatalf("空库应回 []，实际 %q", body)
	}
	if w.Header().Get("X-Total-Count") != "0" {
		t.Fatalf("缺少 X-Total-Count: %q", w.Header().Get("X-Total-Count"))
	}
}

// TestListTasksPagingAndFilter 列表分页、状态筛、元信息。
func TestListTasksPagingAndFilter(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	base := time.Date(2026, 4, 1, 9, 0, 0, 0, time.Local)
	seedTask(t, st, "t1", "done", base)
	seedTask(t, st, "t2", "error", base.Add(time.Hour))
	seedTask(t, st, "t3", "cancelled", base.Add(2*time.Hour))

	w := doReq(t, h, http.MethodGet, "/api/tasks", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d", w.Code)
	}
	var list []discoverTask
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("任务数不符: %d", len(list))
	}
	if list[0].ID != "t3" {
		t.Fatalf("未按开始时间倒序: %s", list[0].ID)
	}
	if w.Header().Get("X-Total-Count") != "3" {
		t.Fatalf("X-Total-Count 不符: %q", w.Header().Get("X-Total-Count"))
	}
	// 目标列表要能从库里还原（换行拼接的存取一致性）
	if len(list[0].Targets) != 1 || list[0].Targets[0] != "10.0.0.0/24" {
		t.Fatalf("目标未还原: %#v", list[0].Targets)
	}

	// 状态筛
	w = doReq(t, h, http.MethodGet, "/api/tasks?status=error", nil, nil)
	var filtered []discoverTask
	_ = json.Unmarshal(w.Body.Bytes(), &filtered)
	if len(filtered) != 1 || filtered[0].ID != "t2" {
		t.Fatalf("状态筛选失效: %#v", filtered)
	}

	// 分页
	w = doReq(t, h, http.MethodGet, "/api/tasks?limit=2", nil, nil)
	var page []discoverTask
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page) != 2 {
		t.Fatalf("limit 未生效: %d", len(page))
	}
	if w.Header().Get("X-Total-Count") != "3" {
		t.Fatalf("分页时 X-Total-Count 应是全量: %q", w.Header().Get("X-Total-Count"))
	}

	// 非法状态值必须报错，而不是静默返回空列表
	w = doReq(t, h, http.MethodGet, "/api/tasks?status=bogus", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法 status 应 400，实际 %d", w.Code)
	}
}

// TestGetTaskNotFound 不存在的任务回 404（而不是 500）。
func TestGetTaskNotFound(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodGet, "/api/tasks/nope", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestCancelTaskNotFound 不存在的任务取消回 404。
func TestCancelTaskNotFound(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodPost, "/api/tasks/nope/cancel", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d", w.Code)
	}
}

// TestCancelFinishedTaskConflict 已结束的任务再点停止应是 409，不是 202。
//
// 假装成功会让用户以为"真的停了"，而实际上什么都没发生。
func TestCancelFinishedTaskConflict(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	seedTask(t, st, "done-1", "done", time.Now().Add(-time.Hour))
	w := doReq(t, h, http.MethodPost, "/api/tasks/done-1/cancel", nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("应 409，实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "done") {
		t.Fatalf("冲突响应应带上当前状态: %s", w.Body.String())
	}
}

// TestCancelRunningTaskCancelsContext 取消一个活任务要真的打断它的 ctx。
//
// 这是"停止扫描"功能的全部价值所在：只改状态不取消 ctx，扫描会继续在后台
// 跑完整个网段，用户看到「已停止」而交换机上的连接还在继续产生。
func TestCancelRunningTaskCancelsContext(t *testing.T) {
	h, st, srv := newTaskRouter(t)
	seedTask(t, st, "live-1", "running", time.Now())

	ctx, cancel := contextWithCancel()
	srv.discMu.Lock()
	srv.discTasks["live-1"] = &discoverTask{
		ID: "live-1", Status: "running", Total: 254, Started: time.Now(),
	}
	srv.discCancel["live-1"] = cancel
	srv.discMu.Unlock()

	w := doReq(t, h, http.MethodPost, "/api/tasks/live-1/cancel", nil, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("应 202，实际 %d: %s", w.Code, w.Body.String())
	}
	select {
	case <-ctx.Done():
		// 正常：取消已传导
	case <-time.After(time.Second):
		t.Fatal("取消请求返回 202 但 ctx 没有被取消——扫描会在后台继续跑完")
	}
}
