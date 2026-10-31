// 端口落库节流的护栏（V1.6）。
//
// 起因：探针每 5 秒重发同一条会话，端口行（含 5 个索引）就跟着每 5 秒重写一遍。
// 9.5 万会话/6.5 次上报每秒的规模下，光"重写没变化的端口"就吃掉了写入路径
// 20% 的时间，WAL 5 分钟涨到 224MB。这个节流是唯一挡住它的地方，
// 所以必须有用例钉住：**第一次写、短时间内不再写、过期后重新写**。
package api

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func TestFilterPortWritesThrottles(t *testing.T) {
	s := &Server{}
	in := []model.PortRecord{
		{IP: "10.0.0.1", Port: 443, Proto: "tcp"},
		{IP: "10.0.0.2", Port: 80, Proto: "tcp"},
	}

	if got := s.filterPortWrites(in); len(got) != 2 {
		t.Fatalf("首次出现必须落库，实际过滤后剩 %d 条", len(got))
	}
	// 同一批再来一次：一个字节都不该写。
	if got := s.filterPortWrites(in); len(got) != 0 {
		t.Fatalf("TTL 内重复上报不应再写库，实际又写了 %d 条", len(got))
	}
	// 新端口不受影响。
	if got := s.filterPortWrites([]model.PortRecord{{IP: "10.0.0.3", Port: 22, Proto: "tcp"}}); len(got) != 1 {
		t.Fatalf("新端口必须落库，实际 %d 条", len(got))
	}

	// 过期后重新落库（把表里的时间拨老，模拟 3 分钟过去）。
	s.portMu.Lock()
	for k := range s.portWrote {
		s.portWrote[k] = time.Now().Add(-portWriteTTL - time.Minute)
	}
	s.portSwept = time.Time{}
	s.portMu.Unlock()
	if got := s.filterPortWrites(in); len(got) != 2 {
		t.Fatalf("超过 TTL 后应重新落库，实际 %d 条", len(got))
	}
}

// TestFilterPortWritesPrunesExpired 过期条目必须被清理，否则内存随端口数无限长。
func TestFilterPortWritesPrunesExpired(t *testing.T) {
	s := &Server{portWrote: map[string]time.Time{}, portSwept: time.Now().Add(-2 * portWriteTTL)}
	old := time.Now().Add(-2 * portWriteTTL)
	for i := 0; i < 1000; i++ {
		s.portWrote[string(rune('a'+i%26))+"-"+time.Now().Format("150405")+"-stale"] = old
	}
	s.filterPortWrites([]model.PortRecord{{IP: "10.0.0.9", Port: 443, Proto: "tcp"}})
	if n := len(s.portWrote); n > 100 {
		t.Fatalf("过期条目没有被清理，表内仍有 %d 条（应只剩刚写入的那条）", n)
	}
}
