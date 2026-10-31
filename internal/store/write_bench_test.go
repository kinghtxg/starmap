// 写入路径的单次成本（V1.6.1 诊断）。
//
// 现场症状：探针上报接口在 9 万会话规模上稳定 3.4 秒/次。上报路径本身只做
// 内存聚合，真正的落库是四件事：会话批量 upsert、端口批量 upsert、
// 探针心跳、审计。这四件各自一次事务，SQLite 只有一个写者，
// 于是"每个请求 4 次抢写锁"。
//
// 这组基准把每一件的单次成本量出来，避免再靠猜：
//
//	go test ./internal/store -bench 'IngestWrite' -benchtime 20x
package store

import (
	"fmt"
	"testing"
	"time"

	"starmap/internal/model"
)

// seedIngestDB 造一个"跑了一天"的库：6 万会话、8 千端口。
func seedIngestDB(b *testing.B) *Store {
	b.Helper()
	st, err := Open(b.TempDir() + "/ingest.db")
	if err != nil {
		b.Fatalf("打开库失败: %v", err)
	}
	const n = 60000
	sessions := make([]model.Session, 0, 1000)
	for i := 0; i < n; i++ {
		sessions = append(sessions, model.Session{
			FiveTuple: model.FiveTuple{SrcIP: fmt.Sprintf("10.%d.%d.%d", 1+i/65536, (i/256)%256, i%256),
				DstIP: fmt.Sprintf("172.16.%d.%d", (i/256)%16, i%256), SrcPort: uint16(1024 + i%60000),
				DstPort: 443, Proto: "tcp"},
			MAC:       fmt.Sprintf("02:ce:%02x:%02x:%02x:01", (i/65536)%256, (i/256)%256, i%256),
			FirstSeen: time.Now(), LastSeen: time.Now(),
			BytesUp: 1024, BytesDown: 4096, Packets: 10,
		})
		if len(sessions) == 1000 {
			if err := st.SaveSessions(sessions); err != nil {
				b.Fatalf("预热写入失败: %v", err)
			}
			sessions = sessions[:0]
		}
	}
	ports := make([]model.PortRecord, 0, 2000)
	for i := 0; i < 8000; i++ {
		ports = append(ports, model.PortRecord{
			NodeKey: "ip:10.0.0.1", IP: fmt.Sprintf("172.16.%d.%d", (i/256)%16, i%256),
			Port: 443, Proto: "tcp", State: "open", Source: model.PortSourceTraffic,
			FirstSeen: time.Now(), LastSeen: time.Now(),
		})
		if len(ports) == 2000 {
			if err := st.UpsertPorts(ports); err != nil {
				b.Fatalf("预热端口失败: %v", err)
			}
			ports = ports[:0]
		}
	}
	return st
}

func benchBatch(n int) []model.Session {
	out := make([]model.Session, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.Session{
			FiveTuple: model.FiveTuple{SrcIP: fmt.Sprintf("10.77.%d.%d", i/256, i%256),
				DstIP: "172.16.0.9", SrcPort: uint16(5000 + i), DstPort: 443, Proto: "tcp"},
			MAC:       fmt.Sprintf("02:df:%02x:%02x:01:01", i/256, i%256),
			FirstSeen: time.Now(), LastSeen: time.Now(),
			BytesUp: 100, BytesDown: 200, Packets: 3,
		})
	}
	return out
}

func BenchmarkIngestWriteSaveSessions80(b *testing.B) {
	st := seedIngestDB(b)
	defer st.Close()
	batch := benchBatch(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.SaveSessions(batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIngestWriteUpsertPorts400(b *testing.B) {
	st := seedIngestDB(b)
	defer st.Close()
	ps := make([]model.PortRecord, 0, 400)
	for i := 0; i < 400; i++ {
		ps = append(ps, model.PortRecord{
			NodeKey: "ip:10.0.0.1", IP: fmt.Sprintf("172.16.%d.%d", (i/256)%16, i%256),
			Port: 443, Proto: "tcp", State: "open", Source: model.PortSourceTraffic,
			FirstSeen: time.Now(), LastSeen: time.Now(),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.UpsertPorts(ps); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIngestWriteUpsertProbe(b *testing.B) {
	st := seedIngestDB(b)
	defer st.Close()
	p := &model.Probe{ProbeID: "stress-0", Name: "probe", Location: "rack-0", LastSeen: time.Now()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.UpsertProbe(p); err != nil {
			b.Fatal(err)
		}
	}
}
