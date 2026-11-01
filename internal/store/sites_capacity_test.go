package store

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestListSitesScales 站点列表的容量守卫。
//
// 站点是 ports 上的派生视图（窗口函数，每个 ip:port 取最新一行），
// 所以它的成本跟**端口表规模**线性相关，而不是跟站点数。一次 /16 全端口扫描
// 能产出几十万行端口，这时候列表页每翻一页都重新算一遍窗口函数是撑不住的——
// 这条用例把"多大规模、多少耗时"钉住，避免以后有人加个 JOIN 就悄悄劣化十倍。
func TestListSitesScales(t *testing.T) {
	if testing.Short() {
		t.Skip("容量用例在 -short 档跳过：CI runner 的磁盘/CPU 与开发机不是一个量级，测出来的是机器不是代码")
	}
	st, err := Open(t.TempDir() + "/scale.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 2 万行端口 = 1 万台主机各 2 个端口；其中一半带 HTTP 特征（成为站点）。
	const hosts = 10000
	now := time.Now()
	batch := make([]model.PortRecord, 0, hosts*2)
	for i := 0; i < hosts; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		batch = append(batch,
			model.PortRecord{
				NodeKey: "ip:" + ip, IP: ip, Port: 8080, Proto: "tcp", State: "open",
				Source: model.PortSourceProbe, HTTPStatus: 200,
				Title: "业务系统", Server: "nginx",
				FirstSeen: now.Add(-24 * time.Hour), LastSeen: now,
			},
			model.PortRecord{
				NodeKey: "ip:" + ip, IP: ip, Port: 22, Proto: "tcp", State: "open",
				Source: model.PortSourceProbe, Service: "ssh",
				FirstSeen: now.Add(-24 * time.Hour), LastSeen: now,
			})
	}
	if err := st.UpsertPorts(batch); err != nil {
		t.Fatalf("灌数据失败: %v", err)
	}

	// 第一页 + 总数：这是列表页每次刷新都会走的两个查询。
	start := time.Now()
	list, err := st.ListSites(SiteFilter{}, 20, 0)
	pageCost := time.Since(start)
	if err != nil {
		t.Fatalf("查站点失败: %v", err)
	}
	if len(list) != 20 {
		t.Fatalf("首页应有 20 条，实际 %d", len(list))
	}

	start = time.Now()
	total, err := st.CountSites(SiteFilter{})
	countCost := time.Since(start)
	if err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if total != hosts {
		t.Fatalf("站点数应为 %d（每台主机一个 Web 端口），实际 %d", hosts, total)
	}

	// 统计页：三个聚合查询。
	start = time.Now()
	stt, err := st.SiteStats(SiteFilter{})
	statsCost := time.Since(start)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if stt.Total != hosts {
		t.Fatalf("统计总数应为 %d，实际 %d", hosts, stt.Total)
	}

	t.Logf("端口 %d 行 / 站点 %d 个：首页 %v，计数 %v，统计 %v",
		len(batch), total, pageCost, countCost, statsCost)

	// 上界取宽松值：这条用例防的是"数量级劣化"（比如误加了一个全表 JOIN，
	// 耗时从 20ms 变成 2s），不是防 10% 的抖动。
	if pageCost > perfBudget(800*time.Millisecond) {
		t.Fatalf("站点首页耗时 %v 超过 800ms 上界（2 万行端口）", pageCost)
	}
	if countCost > perfBudget(800*time.Millisecond) {
		t.Fatalf("站点计数耗时 %v 超过 800ms 上界", countCost)
	}
	if statsCost > perfBudget(2*time.Second) {
		t.Fatalf("站点统计耗时 %v 超过 2s 上界", statsCost)
	}
}

// BenchmarkListSites 首页查询的基准（用于对比后续优化的效果）。
func BenchmarkListSites(b *testing.B) {
	st, err := Open(":memory:")
	if err != nil {
		b.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	batch := make([]model.PortRecord, 0, 4000)
	for i := 0; i < 2000; i++ {
		ip := fmt.Sprintf("10.20.%d.%d", i/256, i%256)
		batch = append(batch, model.PortRecord{
			NodeKey: "ip:" + ip, IP: ip, Port: 8080, Proto: "tcp", State: "open",
			Source: model.PortSourceProbe, HTTPStatus: 200, Title: "业务系统",
			FirstSeen: now.Add(-time.Hour), LastSeen: now,
		})
	}
	if err := st.UpsertPorts(batch); err != nil {
		b.Fatalf("灌数据失败: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.ListSites(SiteFilter{}, 20, 0); err != nil {
			b.Fatal(err)
		}
	}
}
