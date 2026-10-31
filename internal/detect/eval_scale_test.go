// 单轮评估的规模基准（V1.5.2 诊断 + 回归）。
//
// 现场形态：客户端与服务器分属两个网络域时，"多网融合"按验收标准 4.8
// （流量命中 ≥2 个 NetDomain → high）会对几乎每台主机成立；中高风险节点
// 又不参与 /24 聚合。于是"节点数 ≈ 主机数"，评估器每轮要做的事按主机数线性增长：
//   - 整表拷一遍会话
//   - 遍历全量节点算网段/域
//   - 读一遍 24h 内的历史事件建去重索引
//
// 而这轮评估是周期性跑的（触发性 2 秒一轮）。一旦单轮耗时超过周期，
// 就变成"评估器 7×24 满负荷"，把所有 HTTP 接口一起拖慢。
//
// 本文件量出各阶段的真实成本，并在超预算时失败——它是"网络变大后服务变卡"
// 这类问题的唯一早期预警。
package detect

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// buildScale 造一个规模为 n 的现场：n 台内网主机、各自一条跨域会话、
// 以及一条已存在的 multi_net 事件（模拟稳态：事件都已经报过了）。
func buildScale(t *testing.T, n int) (*Detector, []model.Session) {
	t.Helper()
	d, eng, _ := newTestDetector(t, fullCfg())
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

	if _, err := d.Evaluate(); err != nil {
		t.Fatalf("首轮评估失败: %v", err)
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
	if len(idx) == 0 {
		t.Fatal("去重索引为空，基准无意义")
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

	// 预算：一轮评估必须明显小于触发性评估的最小间隔（2 秒），
	// 否则评估器会连轴转，把整个进程的 CPU 吃满。
	if totalCost > 2*time.Second {
		t.Fatalf("单轮评估 %v 超过 2 秒预算：网络再大一点就会把服务拖死", totalCost)
	}
}
