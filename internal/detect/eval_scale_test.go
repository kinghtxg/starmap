// 单轮评估的规模基准（V1.5.2 诊断 + 回归）。
//
// 现场形态：上万台主机的网络里，评估器每轮要做的事按主机数线性增长：
//   - 整表拷一遍会话
//   - 遍历全量节点算网段/域
//   - 读一遍 24h 内的历史事件建去重索引
//   - 候选去重后落库
//
// 而这轮评估是周期性跑的（触发性 5 秒一轮）。一旦单轮耗时逼近周期，
// 就变成"评估器 7×24 满负荷"，把所有 HTTP 接口一起拖慢。
//
// 本文件量出各阶段的真实成本，并在超预算时失败——它是"网络变大后服务变卡"
// 这类问题的唯一早期预警。
//
// V1.6.0 更正：本文件原来断言"客户端与服务器分属两个域 → 每台主机都是
// multi_net"，把这当成正常验收行为。实际那是 evalMultiNet 的误报：
// 它把"访问过的域"当成了"接入的域"，4 万节点能产出 3.9 万个 high 事件。
// 规则已修，基准随之改成"稳态：事件都已报过"这一真实形态。
package detect

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// buildScale 造一个规模为 n 的现场：n 台内网主机、各自一条会话，
// 外加 n 条"已经报过"的历史事件（稳态）。
//
// 稳态才是长期运行时的真实形态：事件在 24h 去重窗口内不会重复新建，
// 每轮评估的开销集中在"建去重索引 + 遍历规则"，而不是写库。
func buildScale(t *testing.T, n int) (*Detector, []model.Session) {
	t.Helper()
	d, eng, st := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{
		{Name: "gov", CIDRs: []string{"10.0.0.0/8"}},
		{Name: "office", CIDRs: []string{"172.16.0.0/12"}},
	})
	ss := make([]model.Session, 0, n)
	for i := 0; i < n; i++ {
		s := model.Session{
			FiveTuple: model.FiveTuple{
				SrcIP:   fmt.Sprintf("10.%d.%d.%d", 1+(i>>16)&0xff, (i>>8)&0xff, i&0xff),
				DstIP:   "172.16.0.9",
				SrcPort: uint16(1024 + i%60000),
				DstPort: 443, Proto: "tcp",
			},
			MAC:       fmt.Sprintf("02:bb:%02x:%02x:%02x:01", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			FirstSeen: base, LastSeen: base.Add(time.Minute),
			BytesUp: 1000, BytesDown: 2000, Packets: 5,
		}
		eng.Ingest(&s)
		ss = append(ss, s)
	}
	sessionList = ss
	d.SessionsFunc = currentSessions

	// 预置事件：模拟"这些主机都已经报过事件"的稳态。
	nodes := eng.AllNodes()
	events := make([]*model.RiskEvent, 0, len(nodes))
	for i := range nodes {
		events = append(events, &model.RiskEvent{
			Type:      model.EventTypeMultiNet,
			NodeID:    nodes[i].ID,
			NodeKey:   nodes[i].NodeKey,
			Title:     "稳态事件",
			Level:     model.RiskHigh,
			Status:    model.EventStatusPending,
			Evidence:  map[string]string{"basis": "subnet", "subnets": "10.0.0.0/24,10.0.1.0/24"},
			CreatedAt: base.Add(time.Minute),
		})
	}
	if _, err := st.CreateEvents(events); err != nil {
		t.Fatalf("预置事件失败: %v", err)
	}
	return d, ss
}

// TestEvaluateCostAtScale 拆解单轮评估各阶段耗时。
func TestEvaluateCostAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("规模基准跳过 -short")
	}
	const n = 20000
	d, _ := buildScale(t, n)

	// ① 拷会话
	t0 := time.Now()
	sessions := d.SessionsFunc()
	copyCost := time.Since(t0)
	if len(sessions) != n {
		t.Fatalf("会话数应为 %d，实际 %d", n, len(sessions))
	}

	// ② 建去重索引
	t0 = time.Now()
	idx := d.buildDedupIndex(d.NowFunc())
	idxCost := time.Since(t0)
	// 节点数会略少于会话数（同网段聚合、地址合并），留 5% 余量。
	if len(idx) < n*95/100 {
		t.Fatalf("去重索引应有约 %d 条（每台主机一条历史事件），实际 %d", n, len(idx))
	}

	// ③ 完整一轮（含规则 + 写库）
	t0 = time.Now()
	created, err := d.Evaluate()
	totalCost := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("规模 %d：拷会话 %v｜建去重索引(%d 条) %v｜完整一轮 %v（新建 %d）",
		n, copyCost.Round(time.Millisecond), len(idx), idxCost.Round(time.Millisecond),
		totalCost.Round(time.Millisecond), len(created))

	// 预算：一轮评估必须明显小于触发性评估的最小间隔（5 秒），
	// 否则评估器会连轴转，把整个进程的 CPU 吃满。
	if totalCost > 2*time.Second {
		t.Fatalf("单轮评估 %v 超过 2 秒预算：网络再大一点就会把服务拖死", totalCost)
	}
}

// TestEvaluateCostWithManyCandidates 候选密集场景的预算。
//
// 稳态之外还有另一种极端：突然出现一批"一机两网"的真实违规主机
// （新接入的设备、刚导入的一段历史流量），候选数在一个周期内暴涨。
// 这条用例保证候选再多，单轮也不会跑成秒级。
func TestEvaluateCostWithManyCandidates(t *testing.T) {
	if testing.Short() {
		t.Skip("规模基准跳过 -short")
	}
	const n = 20000
	d, eng, _ := newTestDetector(t, fullCfg())
	eng.SetDomains([]model.NetDomain{
		{Name: "gov", CIDRs: []string{"10.0.0.0/8"}},
		{Name: "office", CIDRs: []string{"172.16.0.0/12"}},
	})
	ss := make([]model.Session, 0, 2*n)
	// 每台主机两个地址、两条会话 → 每台都是真实的"一机两网"候选。
	for i := 0; i < n; i++ {
		mac := fmt.Sprintf("02:cc:%02x:%02x:%02x:01", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		a := model.Session{
			FiveTuple: model.FiveTuple{SrcIP: fmt.Sprintf("10.%d.%d.%d", 1+(i>>16)&0xff, (i>>8)&0xff, i&0xff),
				DstIP: "172.16.0.9", SrcPort: uint16(1024 + i%60000), DstPort: 443, Proto: "tcp"},
			MAC: mac, FirstSeen: base, LastSeen: base.Add(time.Minute),
			BytesUp: 1000, BytesDown: 2000, Packets: 5,
		}
		b := a
		b.FiveTuple.SrcIP = fmt.Sprintf("192.168.%d.%d", 1+i%250, 1+i%200)
		b.FiveTuple.SrcPort = uint16(2048 + i%60000)
		eng.Ingest(&a)
		eng.Ingest(&b)
		ss = append(ss, a, b)
	}
	sessionList = ss
	d.SessionsFunc = currentSessions

	t0 := time.Now()
	created, err := d.Evaluate()
	cost := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("候选密集：%d 台主机 / %d 台命中一机两网，单轮 %v", n, len(created), cost.Round(time.Millisecond))
	// 同上：同网段聚合会让一部分主机合并到聚合节点，留 5% 余量。
	if len(created) < n*95/100 {
		t.Fatalf("应有约 %d 条 multi_net 事件，实际 %d", n, len(created))
	}
	if cost > 3*time.Second {
		t.Fatalf("候选密集场景单轮 %v 超过 3 秒预算", cost)
	}
}
