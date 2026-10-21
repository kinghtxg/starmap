package topology

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// 性能基线（V1.0 定版）。
//
// 为什么需要这个：StarMap 的真实战场是政务网/隔离内网，一个中等规模的网段
// 就有几千台设备，全网可能上万节点。拓扑引擎的 Snapshot / visibleEdges / Proxies
// 都是被 2 秒一次的同步循环 + 每个 HTTP 请求反复调用的热路径，
// 必须有一份"多大图大概多慢"的量化基线，否则性能回归无人察觉。
//
// 跑法：go test ./internal/topology/ -bench=. -benchmem
// 阈值断言见 TestSnapshotScaleBudget（CI 门禁用宽松上限，只拦数量级恶化）。

const benchCfgAggThreshold = 20

func benchCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds:       86400,
		AggregateThreshold: benchCfgAggThreshold,
		NoiseBytes:         400, NoisePackets: 4, NoiseDurationSec: 2,
		ReverseProxyHosts: 10, LongConnSeconds: 3600, HeartbeatMaxBytes: 64,
	}
}

// buildLargeTopology 构造一个 n 台主机、每台 3 条跨网段会话的拓扑。
//
// 刻意「薄铺网段」：每个 /24 只放 hostsPerSubnet 台（低于聚合阈值），
// 这样 n 台主机全部作为独立节点可见 —— 这是渲染与快照的最坏情况。
// 如果改成每 /24 塞满主机，聚合会把它们压成一个节点，压力根本没打到位（容易得出虚假的乐观结论）。
func buildLargeTopology(tb testing.TB, n int) *Engine {
	tb.Helper()
	const hostsPerSubnet = 5
	e := New(benchCfg())
	now := time.Now()

	ipOf := func(i int) string {
		s := i / hostsPerSubnet
		h := i%hostsPerSubnet + 1
		return fmt.Sprintf("10.%d.%d.%d", 10+s/256, s%256, h)
	}

	for i := 0; i < n; i++ {
		src := ipOf(i)
		for k := 0; k < 3; k++ {
			// 跨网段互访：避免两端落在同一聚合节点而变成自环被丢弃
			j := (i*7 + 13 + k*131) % n
			if j == i {
				j = (i + 1) % n
			}
			e.Ingest(&model.Session{
				FiveTuple: model.FiveTuple{
					SrcIP: src, DstIP: ipOf(j),
					SrcPort: uint16(40000 + (i+k)%2000), DstPort: 80, Proto: "tcp",
				},
				FirstSeen: now.Add(-time.Minute), LastSeen: now,
				BytesUp: 2048, BytesDown: 8192, Packets: 20,
			})
		}
	}
	return e
}

func BenchmarkEngineIngest(b *testing.B) {
	e := New(benchCfg())
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := fmt.Sprintf("10.1.%d.%d", (i/256)%256, i%256)
		dst := fmt.Sprintf("10.2.%d.%d", (i/256)%256, i%256)
		e.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{SrcIP: src, DstIP: dst, SrcPort: uint16(40000 + i%2000), DstPort: 443, Proto: "tcp"},
			FirstSeen: now, LastSeen: now, BytesUp: 1024, BytesDown: 4096, Packets: 10,
		})
	}
}

func BenchmarkSnapshot5k(b *testing.B) {
	e := buildLargeTopology(b, 5000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap := e.Snapshot()
		if len(snap.Nodes) == 0 {
			b.Fatal("快照为空")
		}
	}
}

func BenchmarkSnapshot10k(b *testing.B) {
	e := buildLargeTopology(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Snapshot()
	}
}

func BenchmarkVisibleEdges10k(b *testing.B) {
	e := buildLargeTopology(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.SnapshotEdgePairs()
	}
}

func BenchmarkAllNodes10k(b *testing.B) {
	e := buildLargeTopology(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.AllNodes()
	}
}

// TestSnapshotScaleBudget 规模预算守卫：1 万节点规模下，单次全量快照必须远快于
// 2 秒的同步周期，否则同步循环会自我堆积（跑不完一轮就该跑下一轮了）。
// 阈值取 300ms，是实测值的 10 倍以上余量 —— 只拦数量级恶化，不拦正常抖动。
func TestSnapshotScaleBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("规模预算检查在 -short 下跳过")
	}
	e := buildLargeTopology(t, 10000)
	if got := len(e.AllNodes()); got < 9000 {
		t.Fatalf("规模构造异常：只有 %d 个节点", got)
	}

	start := time.Now()
	snap := e.Snapshot()
	edges := e.SnapshotEdgePairs()
	elapsed := time.Since(start)

	if len(snap.Nodes) == 0 || len(edges) == 0 {
		t.Fatalf("快照为空：nodes=%d edges=%d", len(snap.Nodes), len(edges))
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("1 万节点全量快照耗时 %v，超过 300ms 预算（同步周期 2s）", elapsed)
	}
	t.Logf("1 万节点快照：%d 显示节点 / %d 显示边，耗时 %v",
		len(snap.Nodes), len(edges), elapsed)
}

// TestProxiesScaleBudget Proxies() 从边集推导，边多时是纯 O(E) 遍历。
// 这里量化它，防止将来在代理数量上来后变成请求级热点。
func TestProxiesScaleBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("规模预算检查在 -short 下跳过")
	}
	e := New(benchCfg())
	now := time.Now()
	// 200 个代理 × 50 客户端 = 1 万条 xff 边
	for p := 0; p < 200; p++ {
		proxy := fmt.Sprintf("10.20.%d.1", p)
		for c := 0; c < 50; c++ {
			client := fmt.Sprintf("10.30.%d.%d", p%256, c+1)
			e.Ingest(&model.Session{
				FiveTuple: model.FiveTuple{SrcIP: proxy, DstIP: "10.99.0.1", SrcPort: uint16(40000 + c), DstPort: 80, Proto: "tcp"},
				FirstSeen: now, LastSeen: now, BytesUp: 1024, BytesDown: 2048, Packets: 8,
				XFF: []string{client}, RealClientIP: client, ProxyHops: 1,
			})
		}
	}

	start := time.Now()
	proxies := e.Proxies()
	elapsed := time.Since(start)

	if len(proxies) == 0 {
		t.Fatal("应识别出代理节点")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("200 个代理下 Proxies() 耗时 %v，超过 200ms 预算", elapsed)
	}
	t.Logf("200 代理 / 1 万 xff 边：Proxies() 耗时 %v", elapsed)
}
