package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func newTaskStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/tasks.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func taskFixture(id string, at time.Time, status string) model.DiscoverTask {
	return model.DiscoverTask{
		ID: id, Targets: []string{"10.0.0.0/24", "10.0.1.5"},
		Profile: "common", ProfileLabel: "常用端口",
		Status: status, Total: 255, Done: 255, Alive: 7, OpenPorts: 12,
		Fingerprints: 3, CreatedBy: "admin", StartedAt: at,
	}
}

// TestDiscoverTaskRoundTrip 任务账写入后能完整读回（含目标列表）。
func TestDiscoverTaskRoundTrip(t *testing.T) {
	st := newTaskStore(t)
	at := time.Date(2026, 3, 4, 10, 0, 0, 0, time.Local)
	if err := st.StartDiscoverTask(taskFixture("discover-a", at, "running")); err != nil {
		t.Fatalf("写任务失败: %v", err)
	}

	got, err := st.GetDiscoverTask("discover-a")
	if err != nil || got == nil {
		t.Fatalf("读任务失败: %v / %v", got, err)
	}
	if got.Status != "running" {
		t.Fatalf("状态不符: %q", got.Status)
	}
	if len(got.Targets) != 2 || got.Targets[0] != "10.0.0.0/24" {
		t.Fatalf("目标未能还原: %#v", got.Targets)
	}
	if !got.StartedAt.Equal(at) {
		t.Fatalf("开始时间漂移: %v != %v", got.StartedAt, at)
	}
	if got.FinishedAt.IsZero() != true {
		t.Fatalf("未结束的任务不该有结束时间: %v", got.FinishedAt)
	}

	// 结束：状态与统计都要落进去
	fin := taskFixture("discover-a", at, "done")
	fin.FinishedAt = at.Add(3 * time.Minute)
	fin.OpenPorts = 42
	if err := st.FinishDiscoverTask(fin); err != nil {
		t.Fatalf("结束任务失败: %v", err)
	}
	got, _ = st.GetDiscoverTask("discover-a")
	if got.Status != "done" || got.OpenPorts != 42 {
		t.Fatalf("结束未覆盖: status=%q open_ports=%d", got.Status, got.OpenPorts)
	}
	if got.FinishedAt.IsZero() {
		t.Fatal("结束时间未写入")
	}
}

// TestFinishDiscoverTaskInsertsWhenMissing 库里没有这条任务时，结束时补插。
//
// 场景：进程刚重启、内存里还接得住一个旧任务（或 StartDiscoverTask 写库失败），
// 结束时如果只 UPDATE 就会 0 行受影响，这次扫描在历史里彻底消失。
func TestFinishDiscoverTaskInsertsWhenMissing(t *testing.T) {
	st := newTaskStore(t)
	at := time.Now().Add(-time.Minute)
	fin := taskFixture("discover-ghost", at, "done")
	fin.FinishedAt = time.Now()
	if err := st.FinishDiscoverTask(fin); err != nil {
		t.Fatalf("结束未记账的任务应补插，却报错: %v", err)
	}
	got, err := st.GetDiscoverTask("discover-ghost")
	if err != nil || got == nil {
		t.Fatalf("补插失败: %v / %v", got, err)
	}
	if got.Status != "done" {
		t.Fatalf("补插后状态不符: %q", got.Status)
	}
}

// TestFinishDiscoverTaskRequiresStatus 空状态必须拒绝，不能把 running 改成空串。
func TestFinishDiscoverTaskRequiresStatus(t *testing.T) {
	st := newTaskStore(t)
	if err := st.StartDiscoverTask(taskFixture("discover-x", time.Now(), "running")); err != nil {
		t.Fatal(err)
	}
	bad := taskFixture("discover-x", time.Now(), "")
	if err := st.FinishDiscoverTask(bad); err == nil {
		t.Fatal("空状态竟然被接受，任务会永远停在 running")
	}
	got, _ := st.GetDiscoverTask("discover-x")
	if got.Status != "running" {
		t.Fatalf("拒绝写入时不该改动原记录: %q", got.Status)
	}
}

// TestListDiscoverTasksOrderAndFilter 列表按开始时间倒序，状态筛有效。
func TestListDiscoverTasksOrderAndFilter(t *testing.T) {
	st := newTaskStore(t)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	// 同一秒起两个任务：排序必须靠 id 兜底，否则分页会重复/漏行
	if err := st.StartDiscoverTask(taskFixture("discover-1", base, "done")); err != nil {
		t.Fatal(err)
	}
	if err := st.StartDiscoverTask(taskFixture("discover-2", base, "done")); err != nil {
		t.Fatal(err)
	}
	if err := st.StartDiscoverTask(taskFixture("discover-3", base.Add(time.Hour), "error")); err != nil {
		t.Fatal(err)
	}

	all, err := st.ListDiscoverTasks("", 10, 0)
	if err != nil {
		t.Fatalf("列任务失败: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("任务数不符: %d", len(all))
	}
	if all[0].ID != "discover-3" {
		t.Fatalf("最新任务未排在最前: %s", all[0].ID)
	}

	errs, _ := st.ListDiscoverTasks("error", 10, 0)
	if len(errs) != 1 || errs[0].ID != "discover-3" {
		t.Fatalf("状态筛选失效: %#v", errs)
	}
	if n, _ := st.CountDiscoverTasks(""); n != 3 {
		t.Fatalf("总数不符: %d", n)
	}
	if n, _ := st.CountDiscoverTasks("done"); n != 2 {
		t.Fatalf("done 计数不符: %d", n)
	}

	// 分页：两页各取 2/1，且不重不漏
	p1, _ := st.ListDiscoverTasks("", 2, 0)
	p2, _ := st.ListDiscoverTasks("", 2, 2)
	if len(p1) != 2 || len(p2) != 1 {
		t.Fatalf("分页条数不符: %d / %d", len(p1), len(p2))
	}
	seen := map[string]bool{}
	for _, x := range append(p1, p2...) {
		if seen[x.ID] {
			t.Fatalf("分页出现重复行: %s", x.ID)
		}
		seen[x.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("分页漏行: %d", len(seen))
	}
}

// TestPruneDiscoverTasks 只保留最近 N 条。
func TestPruneDiscoverTasks(t *testing.T) {
	st := newTaskStore(t)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	for i := 0; i < 6; i++ {
		id := "discover-" + string(rune('a'+i))
		if err := st.StartDiscoverTask(taskFixture(id, base.Add(time.Duration(i)*time.Minute), "done")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.PruneDiscoverTasks(2)
	if err != nil {
		t.Fatalf("裁剪失败: %v", err)
	}
	if n != 4 {
		t.Fatalf("应删 4 条，实际 %d", n)
	}
	left, _ := st.ListDiscoverTasks("", 10, 0)
	if len(left) != 2 {
		t.Fatalf("剩余条数不符: %d", len(left))
	}
	// 留下的是最新的两条
	if left[0].ID != "discover-f" || left[1].ID != "discover-e" {
		t.Fatalf("裁剪后剩下的不是最新的: %s, %s", left[0].ID, left[1].ID)
	}
	// keep<=0 是"不裁剪"，不是"全删"——后者会让一次配置失误清空全部历史
	if n, err := st.PruneDiscoverTasks(0); err != nil || n != 0 {
		t.Fatalf("keep=0 应为空操作: n=%d err=%v", n, err)
	}
}

// TestReapInterruptedDiscoverTasks 重启后把遗留的 running 收尾，且不碰已结束的。
func TestReapInterruptedDiscoverTasks(t *testing.T) {
	st := newTaskStore(t)
	now := time.Now()
	if err := st.StartDiscoverTask(taskFixture("run-1", now, "running")); err != nil {
		t.Fatal(err)
	}
	if err := st.StartDiscoverTask(taskFixture("done-1", now, "done")); err != nil {
		t.Fatal(err)
	}
	n, err := st.ReapInterruptedDiscoverTasks(now)
	if err != nil {
		t.Fatalf("收尾失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只收尾 1 条，实际 %d", n)
	}
	run, _ := st.GetDiscoverTask("run-1")
	if run.Status != "error" || run.FinishedAt.IsZero() {
		t.Fatalf("遗留任务未正确收尾: status=%q finished=%v", run.Status, run.FinishedAt)
	}
	done, _ := st.GetDiscoverTask("done-1")
	if done.Status != "done" {
		t.Fatalf("不该改动已结束任务: %q", done.Status)
	}
	// 幂等：再跑一次不应该再改任何东西
	if n, _ := st.ReapInterruptedDiscoverTasks(now); n != 0 {
		t.Fatalf("重复收尾不该有副作用: %d", n)
	}
}

// TestParseTargets 目标字符串还原（多种分隔符混写）。
func TestParseTargets(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"10.0.0.0/24", []string{"10.0.0.0/24"}},
		{"10.0.0.0/24\n10.0.1.5", []string{"10.0.0.0/24", "10.0.1.5"}},
		{"10.0.0.0/24, 10.0.1.5;10.0.2.0/24", []string{"10.0.0.0/24", "10.0.1.5", "10.0.2.0/24"}},
		{"  \n \n ", nil},
	}
	for _, c := range cases {
		got := ParseTargets(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("%q 解析结果不符: %#v", c.in, got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%q 第 %d 项不符: %q", c.in, i, got[i])
			}
		}
	}
}
