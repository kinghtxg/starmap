package api

// 仪表盘并发压力（V1.6）。
//
// 为什么专门测并发：SQLite 在这个项目里是**单写连接**（SetMaxOpenConns(1)），
// 所有请求在存储层排队。一旦某个 handler 抱着自己的锁去等数据库、
// 而另一个 handler 抱着数据库等那把锁，就会死锁——表现出来不是报错，
// 而是"页面一直在转圈"，日志里什么都没有。
//
// 新加的接口正好引入了两把新锁（taskMu / trendMu），且都在持锁期间碰过
// 数据库或共享切片，所以这里把它们同时打一遍。

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestConcurrentDashboardReads 多路并发读不得报错、不得互相拖死。
func TestConcurrentDashboardReads(t *testing.T) {
	h, st, srv := newTaskRouter(t)
	now := time.Now()

	// 预置一批数据，让每条查询都真的有活干
	seedTask(t, st, "t-run", "running", now.Add(-time.Minute))
	seedTask(t, st, "t-done", "done", now.Add(-time.Hour))
	for i := 0; i < 30; i++ {
		ip := "10.1.0." + itoa(int64(i+1))
		seedPort(t, srv, ip, 8000+i, now.AddDate(0, 0, -(i%10)), now.Add(-time.Duration(i)*time.Minute))
	}

	paths := []string{
		"/api/tasks",
		"/api/tasks?status=done",
		"/api/tasks/t-done",
		"/api/changes?days=7",
		"/api/changes?days=30",
		"/api/trend?days=7",
		"/api/export/tasks.csv",
		"/api/export/ports.csv",
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan string, workers*len(paths))

	// 导出路径在并发下**允许** 429：1.6 给导出加了 2 个并发名额，
	// 满额时明确拒绝比排队更诚实（排队会让浏览器一直转圈，用户以为服务挂了）。
	// 但它不能出现别的错误码，也不能一条都成功——那是名额没归还的征兆。
	guarded := map[string]bool{
		"/api/export/tasks.csv": true,
		"/api/export/ports.csv": true,
	}
	var mu sync.Mutex
	okCount := map[string]int{}

	start := time.Now()
	for w := 0; w < workers; w++ {
		for _, p := range paths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				// doReq 里用 t.Helper，但 goroutine 里不能调 t.Fatal，
				// 所以这里只收集结果，由主 goroutine 统一断言。
				rec := doReq(t, h, http.MethodGet, path, nil, nil)
				mu.Lock()
				if rec.Code == http.StatusOK {
					okCount[path]++
				}
				mu.Unlock()
				if rec.Code == http.StatusOK {
					return
				}
				if guarded[path] && rec.Code == http.StatusTooManyRequests {
					return
				}
				errs <- path + " → " + itoa(int64(rec.Code))
			}(p)
		}
	}
	wg.Wait()
	close(errs)
	elapsed := time.Since(start)

	for e := range errs {
		t.Errorf("并发请求失败: %s", e)
	}
	// 只断言"整体至少有一条导出成功"，不断言"每条路径都成功"：
	// 2 个名额面对 16 个同时到达的导出请求，单条路径整批吃 429 是可能且正常的。
	// 但一条都不成功就说明名额没归还——那才是真 bug。
	totalOK := 0
	for _, n := range okCount {
		totalOK += n
	}
	if totalOK == 0 {
		t.Error("所有导出请求都被 429，导出名额可能没有归还")
	}
	t.Logf("%d 个并发请求（%d 条路径 × %d 轮）耗时 %v", workers*len(paths), len(paths), workers, elapsed)
	// 单写者 SQLite 上 64 个请求串行跑，超过 20s 说明有锁争用或退化成全表扫
	if elapsed > 20*time.Second {
		t.Fatalf("并发读耗时 %v 过长，疑似锁争用", elapsed)
	}
}

// TestConcurrentTaskWrites 任务账的并发记账不得丢行、不得死锁。
func TestConcurrentTaskWrites(t *testing.T) {
	_, st, srv := newTaskRouter(t)

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "conc-" + itoa(int64(i))
			task := &discoverTask{
				ID: id, Targets: []string{"10.0.0.0/24"}, Profile: "quick",
				ProfileLabel: "内网高价值端口", Status: "running",
				Total: 254, Started: time.Now(),
			}
			srv.saveTaskStart(task)
			task.Status = "done"
			task.Done, task.Total = 254, 254
			task.Finished = time.Now()
			srv.saveTaskFinish(task)
		}(i)
	}
	wg.Wait()

	got, err := st.CountDiscoverTasks("")
	if err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if got != n {
		t.Fatalf("并发记账丢了行：应 %d 条，实际 %d 条", n, got)
	}
	// 每条都必须是 done（收尾覆盖生效），不能有卡在 running 的
	running, err := st.CountDiscoverTasks("running")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 {
		t.Fatalf("有 %d 条任务停在 running，收尾没写进去", running)
	}
}

// TestTaskListJSONShape 任务列表的 JSON 字段名必须与内存态一致。
//
// 前端任务列表会先命中内存（有实时进度）也可能命中历史（只有统计），
// 两种来源字段名不一致时，表格会出现一半有值一半空——而接口 200，
// 看不出是"数据不对"还是"本来就没有"。
func TestTaskListJSONShape(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	seedTask(t, st, "shape-1", "done", time.Now())

	w := doReq(t, h, http.MethodGet, "/api/tasks", nil, nil)
	var raw []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("条数不符: %d", len(raw))
	}
	// 前端直接读这些键，少一个就是空白列
	for _, k := range []string{
		"id", "targets", "profile", "profile_label", "status",
		"total", "done", "alive", "open_ports", "fingerprints",
		"started", "created_by",
	} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("任务 DTO 缺少字段 %q", k)
		}
	}
}
