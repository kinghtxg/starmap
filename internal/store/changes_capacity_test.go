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
	"strings"
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

// assertNoFullScan 断言一条查询的执行计划里没有 `SCAN ports`（全表扫描）。
//
// 这是变更视图真正的回归守卫。绝对耗时会被三件事干扰——首次读的冷缓存、
// 行宽、以及跑测试的磁盘——而"成本不随表总量增长"这件事只有一个判据：
// 优化器必须走索引定位，而不是把 ports 从头扫一遍。
// 1.6.0 那次 395ms → 40ms 的修复，本质就是把这个 `SCAN` 换成了 `SEARCH`。
func assertNoFullScan(t *testing.T, s *Store, label, query string, args ...any) {
	t.Helper()
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatalf("%s：取执行计划失败: %v", label, err)
	}
	defer rows.Close()
	var plans []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("%s：读执行计划失败: %v", label, err)
		}
		plans = append(plans, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s：%v", label, err)
	}
	if len(plans) == 0 {
		t.Fatalf("%s：执行计划为空，EXPLAIN 没生效", label)
	}
	for _, p := range plans {
		if strings.HasPrefix(p, "SCAN ports") {
			t.Fatalf("%s：退化成全表扫描（%s），成本会随表总量增长\n完整计划: %v",
				label, p, plans)
		}
	}
	t.Logf("%s 计划: %v", label, plans)
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

	since := now.AddDate(0, 0, -7)
	until := now.Add(time.Minute)
	assertNoFullScan(t, st, "7 天新增计数",
		`SELECT COUNT(*) FROM ports WHERE first_seen >= ? AND first_seen < ?`, since, until)
	assertNoFullScan(t, st, "7 天消失计数",
		`SELECT COUNT(*) FROM ports WHERE last_seen < ? AND first_seen < ?`, since, until)

	start := time.Now()
	added, gone, at, gt, err := st.PortChanges(
		ChangeWindow{Since: since, Until: until}, 500)
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
	if budget := perfBudget(200 * time.Millisecond); elapsed > budget {
		t.Fatalf("变更查询耗时 %v 超过 %v 上界——窗口条件没有覆盖索引", elapsed, budget)
	}
}

// TestPortChangesNarrowWindowFast 窄窗口（1 天）在大表上必须接近瞬时。
//
// 这是变更页最常用的姿势："今天网里多了什么"。它与宽窗口的成本差
// 必须来自结果集大小，而不是表总量。
//
// 断言分两半，因为绝对耗时守不住这条语义：
//
//   - **主守卫**是执行计划——必须是 SEARCH + 索引，不能出现 `SCAN ports`。
//     只要走索引，"成本不随表总量增长"就成立，这是 1.6.0 那次
//     395ms → 40ms 修复所换来的东西。
//   - 绝对上界只防数量级跳变（ms → s），所以留足余量。
//     1.7 把上界从 80ms 放到 150ms 不是放宽标准，而是这一版给 ports 加了
//     6 个证书列（server/http_status/http_location/cert_issuer/cert_expiry/
//     self_signed），行宽从 17 列涨到 23 列——**首批读的 500 行要碰更多页**。
//     实测同一台机器同一份数据：1.6 行宽下 60~75ms，1.7 行宽下 71~98ms。
//     这个成本是换取"站点视图能显示证书到期与自签"付的，值得；
//     但把预算留在 80ms 就成了靠运气过的断言。
func TestPortChangesNarrowWindowFast(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	since := now.AddDate(0, 0, -1)
	until := now.Add(time.Minute)
	// 执行计划的断言放在计时之前：它读的是优化器输出，不受缓存冷暖影响。
	addedWhere := `first_seen >= ? AND first_seen < ?`
	goneWhere := `last_seen < ? AND first_seen < ?`
	assertNoFullScan(t, st, "1 天新增计数", `SELECT COUNT(*) FROM ports WHERE `+addedWhere, since, until)
	assertNoFullScan(t, st, "1 天消失计数", `SELECT COUNT(*) FROM ports WHERE `+goneWhere, since, until)
	q1, a1 := applyPage(portColumns+` WHERE `+addedWhere+` ORDER BY first_seen DESC, id DESC`, []any{since, until}, 500, 0)
	q2, a2 := applyPage(portColumns+` WHERE `+goneWhere+` ORDER BY last_seen DESC, id DESC`, []any{since, until}, 500, 0)
	assertNoFullScan(t, st, "1 天新增分页", q1, a1...)
	assertNoFullScan(t, st, "1 天消失分页", q2, a2...)

	start := time.Now()
	added, gone, _, _, err := st.PortChanges(
		ChangeWindow{Since: since, Until: until}, 500)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	t.Logf("5 万行/1 天窗口：added=%d gone=%d 耗时 %v", len(added), len(gone), elapsed)
	if budget := perfBudget(150 * time.Millisecond); elapsed > budget {
		t.Fatalf("窄窗口耗时 %v 超过 %v 上界（此时应已是数量级退化）", elapsed, budget)
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
	if budget := perfBudget(800 * time.Millisecond); elapsed > budget {
		t.Fatalf("趋势查询耗时 %v 超过 %v 上界", elapsed, budget)
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
	if listCost > perfBudget(100*time.Millisecond) || pruneCost > perfBudget(300*time.Millisecond) {
		t.Fatalf("任务账操作过慢：列表 %v / 裁剪 %v", listCost, pruneCost)
	}
}

// TestMarkStalePortsScales 端口状态刷新在 5 万行上的成本（维护循环每轮都会调）。
//
// 这条用例守的不是"总耗时"——分块之后总耗时反而略高于整批（多几次事务提交），
// 真正要守的是**单次持锁时长**：维护循环每跑一轮，探针上报不能被挡住。
//
// 1.7.0 修正（重要）：这条用例原来断言总耗时 < 2s，与它自己的注释矛盾——
// 分块写入的总耗时 = 批数 × (更新成本 + 一次提交落盘)，落盘成本是磁盘的、
// 不是代码的。实测同一份代码：空闲时 0.3s，与其他包并行跑时 3.07s 直接红。
// **用总耗时守"单批持锁时长"，测的是磁盘心情。**
//
// 现在改成读 stalePortStats 的逐批回调，直接判两件事：
//   - 批数必须与 5000 一批相符（防止退化成"一条 UPDATE 打全表"）；
//   - 任意单批的耗时不超过上界（防止单批变成大事务）。
//
// 为什么在 -short 下跳过：单批里仍有一次落盘，CI `-short` 那一档的 runner
// 磁盘 fsync 慢一个数量级，测出来的仍是磁盘成本。
//
// 上界要过 perfBudget 折一道：覆盖率 job 自己带 -cover，插桩会让这条用例变慢。
// 见 perf_test.go。
func TestMarkStalePortsScales(t *testing.T) {
	// -race 下慢 5~10 倍，耗时预算必然误报；这条断言只在普通构建里有效
	if raceEnabled {
		t.Skip("-race 构建下跳过耗时断言")
	}
	if testing.Short() {
		t.Skip("-short 下的 runner 磁盘差异远大于代码差异，耗时断言不可比")
	}
	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 50000, now)

	type batchStat struct {
		rows int64
		cost time.Duration
	}
	var stats []batchStat
	old := stalePortStats
	stalePortStats = func(batch int, rows int64, cost time.Duration) {
		stats = append(stats, batchStat{rows, cost})
	}
	t.Cleanup(func() { stalePortStats = old })

	n, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("标记 stale 失败: %v", err)
	}
	if n == 0 {
		t.Fatal("一条都没标记到，条件写错了")
	}

	// 1) 批数与批量：n 行按 stalePortChunk 分，最后多一次空转确认收敛
	wantBatches := int((n+int64(stalePortChunk)-1)/int64(stalePortChunk)) + 1
	if len(stats) != wantBatches {
		t.Fatalf("批数 %d，期望 %d（每条 UPDATE 打全表的话这里会是 1）", len(stats), wantBatches)
	}
	for i, b := range stats {
		if b.rows > int64(stalePortChunk) {
			t.Fatalf("第 %d 批改了 %d 行，超过批量上限 %d——分块失效", i+1, b.rows, stalePortChunk)
		}
	}
	if last := stats[len(stats)-1]; last.rows != 0 {
		t.Fatalf("最后一批应空转（0 行）确认收敛，实际改了 %d 行", last.rows)
	}

	// 2) 单批持锁时长：这才是真正要守的指标
	var worst time.Duration
	for _, b := range stats {
		if b.cost > worst {
			worst = b.cost
		}
	}
	t.Logf("5 万行：标记 %d 条为 stale，分 %d 批，单批最慢 %v", n, len(stats), worst)
	if budget := perfBudget(1 * time.Second); worst > budget {
		t.Fatalf("单批持锁 %v 超过上界 %v——这一批在持有写锁期间会挡住探针上报", worst, budget)
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

// TestMarkStalePortsChunkLoop 分块循环的边界：末批余数、跨批连续、总数不重不漏。
//
// 把批次调到 7（不是 2000 的因数），确保最后一轮只处理余数、且循环能自己收敛。
// 分块最怕的两种错法都在这里被挡住：漏掉末批（少标），或者条件写松了导致
// 已经 stale 的行被反复计入（多标、死循环）。
func TestMarkStalePortsChunkLoop(t *testing.T) {
	old := stalePortChunk
	stalePortChunk = 7
	t.Cleanup(func() { stalePortChunk = old })

	st := newChangeStore(t)
	now := time.Now()
	seedPortsBulk(t, st, 100, now)

	n, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("分块标记失败: %v", err)
	}
	if n == 0 {
		t.Fatal("应标记到端口，实际 0 条")
	}
	// 再跑一次必须收敛（否则就是死循环的温床）
	n2, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("二次标记失败: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("批次 7 的条件下重复标记改动了 %d 行", n2)
	}
}
