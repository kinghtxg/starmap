// 事件去重的规模门禁（V1.5.2 P0）。
//
// 背景：findRecent 原来是「每个候选事件都查两次库」——ListEvents 全表读 + 线性扫描。
// 候选数随节点数增长，于是单轮评估是 O(N²) 次行读取。实测现场：
//
//	1000 会话 → 单轮 13 秒，3000 会话 → 42 秒，且这条路径挂在 HTTP 上报接口里，
//	探针每 5 秒上报一次就会把数据接入彻底堵死。
//
// 现在一轮只建一次索引，本文件守住这个性质。
package detect

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// frpFleet 造 n 条互不相同的 FRP 候选：每台主机一条，命中 ja4 + 长连接两项。
func frpFleet(n int) []model.Session {
	out := make([]model.Session, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.Session{
			FiveTuple: model.FiveTuple{
				SrcIP:   fmt.Sprintf("192.168.%d.%d", 1+i/250, 1+i%250),
				DstIP:   "203.0.113.50",
				SrcPort: uint16(20000 + i%40000),
				DstPort: 7000,
				Proto:   "tcp",
			},
			MAC:        fmt.Sprintf("aa:bb:cc:%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			JA4:        "t13d1516h2_8daaf6152771_b186095e22b6",
			FirstSeen:  base,
			LastSeen:   base.Add(2 * time.Hour),
			IsLongConn: true,
			BytesUp:    5000, BytesDown: 5000, Packets: 50,
		})
	}
	return out
}

// TestEvaluateDedupScalesWithStateNotQuadratically 守住「去重不是 O(N²)」。
//
// 第二轮评估时每个候选都会命中已有事件——这正是旧实现在每个候选上做全表查询的地方。
// 旧实现在这里要跑几十秒，新实现应在亚秒级。
func TestEvaluateDedupScalesWithStateNotQuadratically(t *testing.T) {
	const n = 1500
	d, eng, _ := newTestDetector(t, fullCfg())
	ss := frpFleet(n)
	for i := range ss {
		eng.Ingest(&ss[i])
	}
	sessionList = ss
	d.SessionsFunc = currentSessions

	// 第一轮：正常产出 n 条事件
	created, err := d.Evaluate()
	if err != nil {
		t.Fatalf("首轮评估失败: %v", err)
	}
	if len(created) != n {
		t.Fatalf("应产生 %d 条事件，实际 %d", n, len(created))
	}

	// 第二轮：n 个候选全部命中 24h 去重窗口 → 只更新证据，不新建
	start := time.Now()
	again, err := d.Evaluate()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("次轮评估失败: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("去重窗口内不应新建事件，实际新建 %d 条", len(again))
	}
	// 旧实现：1500 候选 × 2 次全表查询 × 1500 行 ≈ 450 万行解码，实测 13 秒以上。
	// 3 秒的上界既能挡住回归，也不会在慢机器上误报。
	if elapsed > 3*time.Second {
		t.Fatalf("次轮评估耗时 %v，去重已退化为随历史事件数平方增长", elapsed)
	}
}

// TestBuildDedupIndexPicksNewest 同键多条事件时保留最新一条（与原 id DESC 语义一致）。
func TestBuildDedupIndexPicksNewest(t *testing.T) {
	d, _, st := newTestDetector(t, fullCfg())
	now := d.NowFunc()

	older := &model.RiskEvent{Type: model.EventTypeFRP, NodeID: 7, Title: "older",
		Status: model.EventStatusPending, Level: model.RiskMid, CreatedAt: now.Add(-2 * time.Hour)}
	newer := &model.RiskEvent{Type: model.EventTypeFRP, NodeID: 7, Title: "newer",
		Status: model.EventStatusPending, Level: model.RiskMid, CreatedAt: now.Add(-time.Hour)}
	ids := make(map[string]int64, 2)
	for _, ev := range []*model.RiskEvent{older, newer} {
		id, err := st.CreateEvent(ev)
		if err != nil {
			t.Fatal(err)
		}
		ev.ID = id // CreateEvent 只返回 id，不回填结构体
		ids[ev.Title] = id
	}

	idx := d.buildDedupIndex(now)
	got := idx.find(model.EventTypeFRP, 7)
	if got == nil {
		t.Fatal("应命中该节点的事件")
	}
	if got.ID != ids["newer"] {
		t.Fatalf("应取最新事件 id=%d，实际 id=%d", ids["newer"], got.ID)
	}
}

// TestBuildDedupIndexSkipsOldAndOtherTypes 窗口外的历史事件与其他类型不得误命中。
func TestBuildDedupIndexSkipsOldAndOtherTypes(t *testing.T) {
	d, _, st := newTestDetector(t, fullCfg())
	now := d.NowFunc()

	stale := &model.RiskEvent{Type: model.EventTypeFRP, NodeID: 11, Title: "stale",
		Status: model.EventStatusPending, Level: model.RiskMid,
		CreatedAt: now.Add(-DedupWindow - time.Hour)} // 超出 24h 去重窗口
	if _, err := st.CreateEvent(stale); err != nil {
		t.Fatal(err)
	}
	other := &model.RiskEvent{Type: model.EventTypeMultiNet, NodeID: 11, Title: "other",
		Status: model.EventStatusPending, Level: model.RiskHigh, CreatedAt: now.Add(-time.Hour)}
	if _, err := st.CreateEvent(other); err != nil {
		t.Fatal(err)
	}

	idx := d.buildDedupIndex(now)
	if ev := idx.find(model.EventTypeFRP, 11); ev != nil {
		t.Fatalf("窗口外事件不应命中，实际命中 id=%d", ev.ID)
	}
	if ev := idx.find(model.EventTypeMultiNet, 11); ev == nil {
		t.Fatal("窗口内的其他类型事件应命中")
	}
}

// TestEvaluateCreatesOneEventPerKeyWithinPass 同一轮里同 (类型,节点) 的多个候选只建一条。
func TestEvaluateCreatesOneEventPerKeyWithinPass(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	// 同一台主机、同一种规则命中的两条会话（不同端口）
	a := frpSession(true, true, false)
	b := frpSession(true, true, false)
	b.FiveTuple.SrcPort = 5001
	for _, s := range []*model.Session{a, b} {
		eng.Ingest(s)
	}
	sessionList = []model.Session{*a, *b}
	d.SessionsFunc = currentSessions

	created, err := d.Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("同节点同类型应合并为 1 条事件，实际 %d 条", len(created))
	}
}

// TestEvaluateSkipsUnchangedEvidenceWrites 证据没变化时不得写库。
//
// 稳态下每轮评估都会重新算出同一批候选。若无条件 UPDATE，
// 「候选数 × 评估频率」= 每秒数千次写，而 SQLite 只有一个写者，
// 整个服务的写路径会被自己的评估占满（实测上报延迟被抬到 17 秒）。
func TestEvaluateSkipsUnchangedEvidenceWrites(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	ss := frpFleet(50)
	for i := range ss {
		eng.Ingest(&ss[i])
	}
	sessionList = ss
	d.SessionsFunc = currentSessions

	if _, err := d.Evaluate(); err != nil {
		t.Fatal(err)
	}
	before, err := st.ListEvents(model.EventStatusPending, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 50 {
		t.Fatalf("应产生 50 条事件，实际 %d", len(before))
	}
	stamp := make(map[int64]time.Time, len(before))
	for i := range before {
		stamp[before[i].ID] = before[i].UpdatedAt
	}

	// 同样的会话再评一遍：证据完全一致，不该产生任何写
	time.Sleep(5 * time.Millisecond) // 让"若是误写"能被时间戳观察到
	if _, err := d.Evaluate(); err != nil {
		t.Fatal(err)
	}
	after, err := st.ListEvents(model.EventStatusPending, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range after {
		if old, ok := stamp[after[i].ID]; ok && !after[i].UpdatedAt.Equal(old) {
			t.Fatalf("事件 %d 的证据没有变化却被重写了（updated_at %v → %v）",
				after[i].ID, old, after[i].UpdatedAt)
		}
	}
}

// TestMergeEvidence 证据合并的语义：新增/变更算变化，完全一致不算。
func TestMergeEvidence(t *testing.T) {
	dst := map[string]string{"a": "1", "b": "2"}
	if mergeEvidence(dst, map[string]string{"a": "1", "b": "2"}) {
		t.Fatal("完全一致不应判定为变化")
	}
	if !mergeEvidence(dst, map[string]string{"b": "3"}) {
		t.Fatal("值变更应判定为变化")
	}
	if dst["b"] != "3" {
		t.Fatalf("合并后应写入新值，实际 %q", dst["b"])
	}
	if !mergeEvidence(dst, map[string]string{"c": "4"}) {
		t.Fatal("新增键应判定为变化")
	}
	if dst["c"] != "4" {
		t.Fatal("新增键应写入")
	}
}
