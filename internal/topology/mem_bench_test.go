// 会话表的内存占用基准（诊断用，不做断言——内存断言在不同 Go 版本/平台上太脆）。
//
// 用法：
//
//	go test ./internal/topology -run XXX -bench BenchmarkSessionMemory -benchmem
//
// 关心的是「每条会话基准占多少字节」：会话上限默认 20 万，
// 如果单条超过 1KB，单机默认配置就要吃 200MB 以上，这在小内存 VPS 上是硬约束。
package topology

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"starmap/internal/model"
)

func TestSessionMemoryFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("内存基准跳过 -short")
	}
	const n = 50000
	e := New(testCfg())

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	now := time.Now()
	for i := 0; i < n; i++ {
		e.Ingest(&model.Session{
			FiveTuple: model.FiveTuple{
				SrcIP:   fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
				DstIP:   "172.16.0.1",
				SrcPort: uint16(1024 + i%60000),
				DstPort: 443,
				Proto:   "tcp",
			},
			MAC:       "02:00:00:00:00:01",
			FirstSeen: now, LastSeen: now,
			BytesUp: 100, BytesDown: 200, Packets: 3,
		})
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// HeapAlloc 差值扣掉 map 结构本身，粗略折算到「每条会话」
	perSession := float64(after.HeapAlloc-before.HeapAlloc) / float64(n)
	t.Logf("引擎会话基准：%d 条，HeapAlloc %d → %d（Δ %.1f MB），约 %.0f 字节/条",
		n, before.HeapAlloc, after.HeapAlloc,
		float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), perSession)
	if snap := e.Snapshot(); len(snap.Nodes) == 0 {
		t.Fatal("会话没有进入引擎，基准无意义")
	}
}
