package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

// SenderConfig 上报参数。
type SenderConfig struct {
	Server   string
	Token    string
	ProbeID  string
	Name     string
	Location string
	Batch    int
	Buffer   int
	Logger   *slog.Logger
	// Client 便于测试注入；为空则用内置客户端。
	Client *http.Client
}

// Sender 上报队列。
//
// 为什么要有队列：服务端重启、网络抖动、机房割接都会让上报失败几秒到几分钟。
// 直接"发失败就丢"看着简单，但代价是这段时间的会话永久丢失，而且日志里
// 只有一行 error——没人会去核对少了几百条会话。所以这里用有界队列先攒着，
// 超上限才丢最旧的，并把丢弃数明确报出来。
type Sender struct {
	cfg    SenderConfig
	url    string
	client *http.Client
	log    *slog.Logger

	mu      sync.Mutex
	queue   []Flow
	sent    int64
	failed  int64
	dropped int64
	backoff time.Duration
	nextTry time.Time // 退避到期时间；零值表示立即可以发
}

// NewSender 构造上报器。
func NewSender(cfg SenderConfig) *Sender {
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 20000
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Sender{
		cfg:    cfg,
		url:    trimSlash(cfg.Server) + "/api/ingest/probe",
		client: client,
		log:    cfg.Logger,
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// Push 入队。队列满时丢弃最旧的会话并计数——宁可丢旧的，也不要让内存无上限增长。
func (s *Sender) Push(flows []Flow) {
	if len(flows) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, flows...)
	s.trimLocked()
}

// trimLocked 把队列压回上限内，返回被丢弃的条数。调用方必须持有锁。
func (s *Sender) trimLocked() {
	over := len(s.queue) - s.cfg.Buffer
	if over <= 0 {
		return
	}
	s.queue = append(s.queue[:0:0], s.queue[over:]...)
	s.dropped += int64(over)
	s.log.Warn("上报队列已满，丢弃最旧会话", "dropped_total", s.dropped, "buffer", s.cfg.Buffer)
}

// Run 后台循环，直到 ctx 结束。
func (s *Sender) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.drainOnce(ctx)
		}
	}
}

// drainOnce 发一批。
//
// 退避不用 time.Sleep：这个函数跑在一秒一跳的 ticker 里，sleep 会把下一次
// tick 也吞掉，实际重试间隔会从 2s 涨到 3s、5s……越滚越大，最后表现为
// "服务端恢复很久了探针还在傻等"。改成记录 nextTry 再比对当前时间，一次不多等。
func (s *Sender) drainOnce(ctx context.Context) {
	s.mu.Lock()
	if time.Now().Before(s.nextTry) {
		s.mu.Unlock()
		return
	}
	n := min(s.cfg.Batch, len(s.queue))
	if n == 0 {
		s.mu.Unlock()
		return
	}
	batch := append([]Flow(nil), s.queue[:n]...)
	// 先摘出队列再发。反过来（发完再切）会有个隐蔽的数据丢失：发送期间 Push
	// 可能因为超限把队首丢掉，等发送成功后再按 n 切一刀，切掉的就是另一批
	// 从未发出过的会话——库里少了几百条，日志里一个错都没有。
	s.queue = s.queue[n:]
	s.mu.Unlock()

	if err := s.post(ctx, batch); err != nil {
		s.mu.Lock()
		s.failed++
		s.backoff = nextBackoff(s.backoff)
		s.nextTry = time.Now().Add(s.backoff)
		failed, bo := s.failed, s.backoff
		// 放回队首，下一轮重发。
		s.queue = append(batch, s.queue...)
		s.trimLocked()
		s.mu.Unlock()
		s.log.Warn("上报失败，稍后重试",
			"err", err, "flows", len(batch), "failed_total", failed, "retry_in", bo.String())
		return
	}

	s.mu.Lock()
	s.sent += int64(len(batch))
	s.backoff = 0
	s.nextTry = time.Time{}
	s.mu.Unlock()
}

func nextBackoff(cur time.Duration) time.Duration {
	if cur == 0 {
		return time.Second
	}
	cur *= 2
	if cur > 30*time.Second {
		cur = 30 * time.Second
	}
	return cur
}

type report struct {
	ProbeID  string    `json:"probe_id"`
	Name     string    `json:"name,omitempty"`
	Location string    `json:"location,omitempty"`
	Token    string    `json:"token,omitempty"`
	SentAt   time.Time `json:"sent_at"`
	Flows    []Flow    `json:"flows"`
}

type reportResp struct {
	Accepted  int `json:"accepted"`
	Total     int `json:"total"`
	Sessions  int `json:"sessions"`
	NewEvents int `json:"new_events"`
}

func (s *Sender) post(ctx context.Context, flows []Flow) error {
	body, err := json.Marshal(report{
		ProbeID:  s.cfg.ProbeID,
		Name:     s.cfg.Name,
		Location: s.cfg.Location,
		Token:    s.cfg.Token,
		SentAt:   time.Now(),
		Flows:    flows,
	})
	if err != nil {
		return fmt.Errorf("编码上报体失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Token != "" {
		req.Header.Set("X-Probe-Token", s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("连接服务端失败: %w", err)
	}
	defer resp.Body.Close()
	// 无论成败都读掉响应体，否则连接无法复用。
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, truncate(string(rb), 200))
	}
	var rr reportResp
	if err := json.Unmarshal(rb, &rr); err == nil && rr.NewEvents > 0 {
		s.log.Info("服务端产生新事件", "new_events", rr.NewEvents, "flows", rr.Accepted)
	}
	return nil
}

// truncate 截断到 n 字节以内，且不会切出半个汉字。
// 服务端的错误信息是中文，按字节硬切会在日志里留一串乱码，反而看不出原因。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// Close 尽力把剩余队列发出去（不重试），然后停止。
func (s *Sender) Close() {
	s.mu.Lock()
	remain := len(s.queue)
	s.mu.Unlock()
	if remain == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		s.mu.Lock()
		n := min(s.cfg.Batch, len(s.queue))
		if n == 0 {
			s.mu.Unlock()
			break
		}
		batch := append([]Flow(nil), s.queue[:n]...)
		s.mu.Unlock()
		if err := s.post(ctx, batch); err != nil {
			s.log.Warn("退出前最后一批上报失败", "err", err, "flows", len(batch))
			break
		}
		s.mu.Lock()
		s.queue = s.queue[n:]
		s.sent += int64(len(batch))
		s.mu.Unlock()
	}
	s.mu.Lock()
	sent, failed, dropped := s.sent, s.failed, s.dropped
	s.mu.Unlock()
	s.log.Info("上报统计", "sent", sent, "failed_posts", failed, "dropped", dropped)
}

// Stats 返回累计计数（测试与退出汇报用）。
func (s *Sender) Stats() (sent, failed, dropped int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.failed, s.dropped
}
