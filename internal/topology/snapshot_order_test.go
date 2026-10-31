package topology

// 拓扑快照排序测试（V1.5.2 新增）。
//
// 旧实现按 APINodeID 字符串排序，主机 ID 是十进制字符串，于是得到
// "1, 10, 11, 2, 20, 3..." 这种字典序。节点少时肉眼看不出来，
// 一多就是明显错乱，而列表与下拉框都直接吃这个顺序。

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func TestSnapshotNodeOrderIsNumeric(t *testing.T) {
	e := New(model.SystemConfig{AgingSeconds: 86400, AggregateThreshold: 1000, NoiseBytes: 1, NoisePackets: 1})
	now := time.Now()

	// 造 12 台主机，会让 ID 跨过 9→10 这个字典序的坑
	for i := 1; i <= 12; i++ {
		e.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{
				SrcIP:   "10.20.0." + itoa(i),
				DstIP:   "10.20.0.1",
				SrcPort: uint16(30000 + i), DstPort: 445, Proto: "tcp",
			},
			BytesUp: 5000, BytesDown: 5000, Packets: 10,
			FirstSeen: now, LastSeen: now,
		})
	}

	snap := e.Snapshot()
	prev := int64(-1)
	hosts := 0
	for _, n := range snap.Nodes {
		// 只看真实主机（聚合节点 ID 是字符串身份，不参与数值序）
		if nodeSortRank(&n) != 0 {
			continue
		}
		hosts++
		if n.ID <= prev {
			t.Fatalf("快照节点顺序错误：%d 排在 %d 之后（应为数值升序）", n.ID, prev)
		}
		prev = n.ID
	}
	if hosts < 12 {
		t.Fatalf("应至少有 12 台主机，实际 %d", hosts)
	}
}

func TestSnapshotGroupOrder(t *testing.T) {
	e := New(model.SystemConfig{AgingSeconds: 86400, AggregateThreshold: 2, NoiseBytes: 1, NoisePackets: 1})
	now := time.Now()

	// 两个 /24 各 3 台 → 触发聚合；再有一台孤立主机；再有一条公网会话 → 外部聚合节点
	for s := 0; s < 2; s++ {
		for i := 1; i <= 3; i++ {
			e.Ingest(&model.Session{
				FiveTuple: model.FiveTuple{
					SrcIP:   "10.3" + itoa(s) + ".0." + itoa(i),
					DstIP:   "10.30.0.1",
					SrcPort: uint16(20000 + i), DstPort: 445, Proto: "tcp",
				},
				BytesUp: 9000, BytesDown: 9000, Packets: 20,
				FirstSeen: now, LastSeen: now,
			})
		}
	}
	e.Ingest(&model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "192.168.77.7", DstIP: "8.8.8.8", SrcPort: 51000, DstPort: 443, Proto: "tcp"},
		BytesUp:   9000, BytesDown: 9000, Packets: 20, FirstSeen: now, LastSeen: now,
	})

	snap := e.Snapshot()
	rank := 0
	for _, n := range snap.Nodes {
		r := nodeSortRank(&n)
		if r < rank {
			t.Fatalf("分组顺序错误：rank=%d 出现在 rank=%d 之后（应为 主机→网段聚合→外部聚合）", r, rank)
		}
		rank = r
	}
}

// itoa 测试内的极小整数转字符串，避免为此引入 strconv。
func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
