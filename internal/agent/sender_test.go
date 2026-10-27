package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mkFlow(tag string) Flow {
	return Flow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Proto: "tcp", SNI: tag}
}

func newTestSender(t *testing.T, url string, buffer int) *Sender {
	t.Helper()
	return NewSender(SenderConfig{
		Server: url, ProbeID: "p1", Batch: 3, Buffer: buffer, Logger: quietLog(),
		Client: &http.Client{Timeout: 2 * time.Second},
	})
}

// TestPushTrimsOldest 队列满时丢最旧的，并且把丢弃数记下来。
// 丢数据可以接受（内存有上限），丢得不明不白不行。
func TestPushTrimsOldest(t *testing.T) {
	s := newTestSender(t, "http://127.0.0.1:1", 4)
	s.Push([]Flow{mkFlow("a"), mkFlow("b")})
	s.Push([]Flow{mkFlow("c"), mkFlow("d")})
	s.Push([]Flow{mkFlow("e")})
	s.mu.Lock()
	got, dropped := len(s.queue), s.dropped
	s.mu.Unlock()
	if got != 4 || dropped != 1 {
		t.Fatalf("队列 %d 丢弃 %d, 期望 4/1", got, dropped)
	}
	s.mu.Lock()
	head := s.queue[0].SNI
	s.mu.Unlock()
	if head != "b" {
		t.Fatalf("队首 = %q, 期望 b（最旧的 a 应被丢掉）", head)
	}
}

// TestDrainRetriesWithoutLoss 失败的那一批必须回到队首重发，而不是丢掉。
// 丢掉看起来"反正服务端也收不到"，实际是静默的数据缺口。
func TestDrainRetriesWithoutLoss(t *testing.T) {
	var calls int32
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var rep report
		_ = json.NewDecoder(r.Body).Decode(&rep)
		mu.Lock()
		for _, f := range rep.Flows {
			got = append(got, f.SNI)
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, 100)
	ctx := context.Background()
	s.Push([]Flow{mkFlow("a"), mkFlow("b"), mkFlow("c")})

	s.drainOnce(ctx) // 第一次：500
	s.mu.Lock()
	afterFail := len(s.queue)
	s.mu.Unlock()
	if afterFail != 3 {
		t.Fatalf("失败后队列 %d, 期望 3（不能丢）", afterFail)
	}

	// 退避期间不应发请求
	s.drainOnce(ctx)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("退避期间发了 %d 次请求, 期望仍是 1", n)
	}

	s.mu.Lock()
	s.nextTry = time.Time{}
	s.mu.Unlock()
	s.drainOnce(ctx) // 退避到期，重发成功

	s.mu.Lock()
	left := len(s.queue)
	s.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if left != 0 {
		t.Fatalf("成功后队列还剩 %d 条", left)
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("服务端收到 %v, 期望 a b c 且顺序不变", got)
	}
}

// TestNoLossWhenPushDuringPost 发送进行中队列被 trim，成功回调不能再切一刀。
//
// 这是原来那段"发完再 s.queue = s.queue[n:]"的真实缺陷：发送期间 Push 可能因为
// 超限把队首丢掉，返回后再按 n 切，切掉的是另一批从未发出过的会话——
// 库里的记录少了几百条，日志里一个错都不会有。
func TestNoLossWhenPushDuringPost(t *testing.T) {
	var once sync.Once
	s := newTestSender(t, "http://127.0.0.1:1", 100)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 在服务端"处理中"这个窗口里塞满队列，触发 trim。
		once.Do(func() {
			batch := make([]Flow, 0, 10)
			for i := 0; i < 10; i++ {
				batch = append(batch, mkFlow(fmt.Sprintf("b%d", i)))
			}
			s.Push(batch)
		})
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()
	s.url = srv.URL + "/api/ingest/probe"

	// Batch=3，恰好把 a0..a2 一次摘空；随后服务端处理期间推入 b0..b9。
	s.Push([]Flow{mkFlow("a0"), mkFlow("a1"), mkFlow("a2")})
	s.cfg.Buffer = 5 // 让 trim 在发送窗口内生效

	s.drainOnce(context.Background())

	s.mu.Lock()
	defer s.mu.Unlock()
	// 摘空后队列为空；推入 b0..b9 共 10 条 → trim 到 5 → [b5..b9]，丢弃 5。
	// 旧的写法还会在成功后按 n=3 再切一刀，把 b5 b6 b7 也丢掉。
	if len(s.queue) != 5 {
		t.Fatalf("队列 %d 条, 期望 5", len(s.queue))
	}
	if s.queue[0].SNI != "b5" {
		t.Fatalf("队首 = %q, 期望 b5（b5 从未被发出过，不能丢）", s.queue[0].SNI)
	}
	if s.dropped != 5 {
		t.Fatalf("dropped = %d, 期望 5", s.dropped)
	}
}

// TestPostSendsTokenAndIdentity 控制面字段走对位置：token 既在 header 也在 body
// （服务端两种都认，header 优先）。
func TestPostSendsTokenAndIdentity(t *testing.T) {
	var hdr, bodyProbe, loc string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Get("X-Probe-Token")
		var rep report
		_ = json.NewDecoder(r.Body).Decode(&rep)
		bodyProbe, loc = rep.ProbeID, rep.Location
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	s := NewSender(SenderConfig{
		Server: srv.URL, Token: "tk", ProbeID: "probe-7", Location: "机房A 镜像口",
		Batch: 10, Buffer: 10, Logger: quietLog(),
	})
	s.Push([]Flow{mkFlow("a")})
	s.drainOnce(context.Background())

	if hdr != "tk" {
		t.Errorf("X-Probe-Token = %q", hdr)
	}
	if bodyProbe != "probe-7" || loc != "机房A 镜像口" {
		t.Errorf("body probe_id=%q location=%q", bodyProbe, loc)
	}
}

// TestDrainReportsServerError 服务端非 200 要当成失败（不能静默丢弃），
// 错误文本要能看出是哪一类问题。
func TestDrainReportsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "探针 token 校验失败", http.StatusUnauthorized)
	}))
	defer srv.Close()
	s := newTestSender(t, srv.URL, 10)
	s.Push([]Flow{mkFlow("a")})
	s.drainOnce(context.Background())
	s.mu.Lock()
	failed, left := s.failed, len(s.queue)
	s.mu.Unlock()
	if failed != 1 || left != 1 {
		t.Fatalf("failed=%d queue=%d, 期望 1/1", failed, left)
	}
}

func TestNextBackoff(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{0, time.Second},
		{time.Second, 2 * time.Second},
		{16 * time.Second, 30 * time.Second},
		{30 * time.Second, 30 * time.Second},
	}
	for _, c := range cases {
		if got := nextBackoff(c.in); got != c.want {
			t.Errorf("nextBackoff(%s) = %s, 期望 %s", c.in, got, c.want)
		}
	}
}

// TestTruncateKeepsRunes 服务端错误信息是中文，按字节硬切会切出半个汉字。
func TestTruncateKeepsRunes(t *testing.T) {
	s := "探针 token 校验失败"
	got := truncate(s, 7) // 落在汉字中间
	if len(got) == 0 || got[len(got)-3:] != "…" {
		t.Fatalf("截断结果异常: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("截断后不是合法 UTF-8: %q", got)
	}
	if truncate("short", 10) != "short" {
		t.Fatal("短串不应被截断")
	}
}

// TestSenderCloseFlushes 退出前要把队列里剩下的发出去。
// 探针正常停机的场景（systemctl stop）全靠这条路径，丢了就是每次运维操作
// 都附赠一段数据空白。
func TestSenderCloseFlushes(t *testing.T) {
	c, srv := newCollector(t)
	s := newTestSender(t, srv.URL, 100)
	s.Push([]Flow{mkFlow("a"), mkFlow("b")})
	s.Close()

	flows, posts := c.snapshot()
	if posts != 1 || len(flows) != 2 {
		t.Fatalf("收到 %d 次上报 / %d 条会话, 期望 1/2", posts, len(flows))
	}
	sent, _, _ := s.Stats()
	if sent != 2 {
		t.Fatalf("sent = %d, 期望 2", sent)
	}
	// Close 之后队列应为空，重复 Close 不应重复发送。
	s.Close()
	if _, posts2 := c.snapshot(); posts2 != 1 {
		t.Fatalf("重复 Close 又发了 %d 次", posts2-posts)
	}
}

// TestSenderRunDrains 后台循环能自己把队列发空。
func TestSenderRunDrains(t *testing.T) {
	c, srv := newCollector(t)
	s := newTestSender(t, srv.URL, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Push([]Flow{mkFlow("a")})
	deadline := time.After(5 * time.Second)
	for {
		flows, _ := c.snapshot()
		if len(flows) == 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("5s 内没发出会话")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestSenderPushEmpty 空批次不应该制造一次无意义的 POST。
func TestSenderPushEmpty(t *testing.T) {
	s := newTestSender(t, "http://127.0.0.1:1", 10)
	s.Push(nil)
	s.mu.Lock()
	n := len(s.queue)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("队列 %d, 期望 0", n)
	}
}
