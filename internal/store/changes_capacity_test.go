package store

// 变更视图与趋势统计的容量回归（V1.6 新增）。
//
// 背景：这两个查询都是"仪表盘/变更页每次打开都会跑"的路径，而 ports 表
// 是全库增长最快的表（一次 /16 全端口扫描就是几十万行）。它们的成本必须
// 只跟**时间窗口内的行数**有关，不能跟表总量有关——否则上线三个月后
// 变更页会从"秒开"变成"转圈十秒"，而代码一行没改。
//
// 断言方式与 parser/capacity_test.go 一致：用绝对上界而不是相对基线。
// 这类回归是数量级跳变（ms → s），上界留足余量就不会在慢机器上误报。

import (
	"fmt"
	"testing"
	"time"
)

// seedPortsBulk 用一条事务批量灌端口记录（逐条 UpsertPort 每条一次提交，
// 5 万行要跑几分钟，测试本身会变成瓶颈）。
func seedPortsBulk(t *testing.T, s *Store, n int, base time.Time) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatalf("开启事务失败: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO ports
		(node_key,ip,port,proto,service,state,source,first_seen,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("预编译失败: %v", err)
	}
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		// 把时间摊到最近 60 天：一半落在 7 天窗口内，一半落在窗口外，
		// 这样两个条件分支都有真实数据要过滤。
		age := time.Duration(i%60) * 24 * time.Hour
		if err := func() error {
			_, e := stmt.Exec("ip:"+ip, ip, 1024+i%60000, "tcp", "http",
				"open", "probe", base.Add(-age), base.Add(-age))
			return e
		}(); err != nil {
			_ = tx.Rollback()
			t.Fatalf("灌数据失败（第 %d 行）: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
}

// TestPortChangesCostDoesNotScaleWithTable 5 万行端口表上，7 天窗口查询要够快。
//
// 这里的数据是**刻意最坏**的：5 万行里 87% 落在窗口外，于是「消失」一侧
// 要数 4.3 万行。实测过一次 395ms 的版本——原因是索引只覆盖 last_seen，
// first_seen 得回表逐行取；换成 (last_seen, first_seen) 复合索引后降到 40ms。
// 上界取 200ms 是为了守住这个索引不被后人"优化"掉。
func TestPortChangesCostDoesNotScaleWithTable(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	start := time.Now()
	added, gone, at, gt, err := st.PortChanges(
		ChangeWindow{Since: now.AddDate(0, 0, -7), Until: now.Add(time.Minute)}, 500)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	// 结果必须非空：灌的数据里有落在窗口内的，返回 0 说明筛选条件写错了
	// （比如时间比较用了字符串序而库里是 RFC3339）。
	if at == 0 && gt == 0 {
		t.Fatalf("5 万行里一条变更都没筛出来，筛选条件可疑（added=%d gone=%d）", at, gt)
	}
	if len(added) > 500 || len(gone) > 500 {
		t.Fatalf("limit 未生效: %d / %d", len(added), len(gone))
	}
	t.Logf("5 万行端口表：added=%d(total %d) gone=%d(total %d) 耗时 %v",
		len(added), at, len(gone), gt, elapsed)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("变更查询耗时 %v 超过 200ms 上界——窗口条件没有覆盖索引", elapsed)
	}
}

// TestPortChangesNarrowWindowFast 窄窗口（1 天）在大表上必须接近瞬时。
//
// 这是变更页最常用的姿势："今天网里多了什么"。它与宽窗口的成本差
// 必须来自结果集大小，而不是表总量。
func TestPortChangesNarrowWindowFast(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	start := time.Now()
	added, gone, _, _, err := st.PortChanges(
		ChangeWindow{Since: now.AddDate(0, 0, -1), Until: now.Add(time.Minute)}, 500)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	t.Logf("5 万行/1 天窗口：added=%d gone=%d 耗时 %v", len(added), len(gone), elapsed)
	if elapsed > 80*time.Millisecond {
		t.Fatalf("窄窗口耗时 %v 超过 80ms，成本没有随窗口收窄", elapsed)
	}
}

// TestTrendStatsCostBounded 30 天趋势在 5 万行端口表上的成本上界。
func TestTrendStatsCostBounded(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	start := time.Now()
	points, err := st.TrendStats(30, now)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("趋势查询失败: %v", err)
	}
	if len(points) != 30 {
		t.Fatalf("序列长度不符: %d", len(points))
	}
	sum := 0
	for _, p := range points {
		sum += p.Ports
	}
	if sum == 0 {
		t.Fatal("30 天里一条新增端口都没统计到，按天分组失效（多半是用了 date() 拿到 NULL）")
	}
	t.Logf("5 万行端口表：30 天新增端口合计 %d，耗时 %v", sum, elapsed)
	if elapsed > 800*time.Millisecond {
		t.Fatalf("趋势查询耗时 %v 超过 800ms 上界", elapsed)
	}
}

// TestPruneDiscoverTasksCostBounded 任务账满 2000 条时的列表与裁剪成本。
func TestPruneDiscoverTasksCostBounded(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newTaskStore(t)
	base := time.Now().Add(-2000 * time.Minute)

	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO discover_tasks
		(id,targets,profile,profile_label,status,total,done,alive,open_ports,fingerprints,error,created_by,started_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("discover-bulk-%d", i), "10.0.0.0/24",
			"quick", "内网高价值端口", "done", 254, 254, 3, 5, 1, "", "admin",
			base.Add(time.Duration(i)*time.Minute)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("灌任务失败（第 %d 条）: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	page, err := st.ListDiscoverTasks("", 20, 100)
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	listCost := time.Since(start)
	if len(page) != 20 {
		t.Fatalf("分页条数不符: %d", len(page))
	}

	start = time.Now()
	n, err := st.PruneDiscoverTasks(500)
	if err != nil {
		t.Fatalf("裁剪失败: %v", err)
	}
	pruneCost := time.Since(start)
	if n != 1500 {
		t.Fatalf("应裁掉 1500 条，实际 %d", n)
	}
	t.Logf("2000 条任务账：列表 %v，裁剪 %v", listCost, pruneCost)
	if listCost > 100*time.Millisecond || pruneCost > 300*time.Millisecond {
		t.Fatalf("任务账操作过慢：列表 %v / 裁剪 %v", listCost, pruneCost)
	}
}

// TestMarkStalePortsScales 端口状态刷新在 5 万行上的成本（维护循环每轮都会调）。
func TestMarkStalePortsScales(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	start := time.Now()
	n, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("标记 stale 失败: %v", err)
	}
	t.Logf("5 万行：标记 %d 条为 stale，耗时 %v", n, elapsed)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("端口状态刷新耗时 %v 超过上界", elapsed)
	}
	// 幂等：再跑一次对已 stale 的行不应重复计数
	n2, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("二次标记失败: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("重复标记改动了 %d 行，条件里漏了 state='open'", n2)
	}
}
