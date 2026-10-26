package probe

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// 内置 TCP 探活 / 端口扫描（纯 Go，不依赖 nmap、不需要 root）。
//
// 为什么要自己实现：
//   - ICMP 在内网被大面积屏蔽（政务网尤甚），只靠 ping 会系统性地漏掉"活着但禁 ping"的设备；
//   - ARP 只在同一广播域有效，跨网段完全看不见；
//   - nmap 在很多内网机器上装不了（软件白名单 / 无外网源）。
//
// TCP connect 是这三条约束下唯一"到处都能用"的探活手段：一次三次握手成功就证明
// 目标主机在线且该端口在监听，且纯用户态、无需特权。
// 代价是比 SYN 扫描慢、且会在目标侧留下连接记录——内网资产盘点场景可以接受。

// ScanOptions 一次端口扫描的参数。
type ScanOptions struct {
	Concurrency int           // 并发连接数（默认 256）
	Timeout     time.Duration // 单端口超时（默认 800ms）
	RatePPS     int           // 全局速率上限（0 = 沿用 Scanner 的限速）
}

// DefaultScanOptions 默认参数。
// 256 并发 / 800ms 超时是实测折中：再高会让廉价交换机管理面抖动，再低 /24 全端口扫描要跑十几分钟。
func DefaultScanOptions() ScanOptions {
	return ScanOptions{Concurrency: 256, Timeout: 800 * time.Millisecond}
}

func (o ScanOptions) normalize() ScanOptions {
	if o.Concurrency <= 0 {
		o.Concurrency = 256
	}
	if o.Concurrency > 2048 {
		o.Concurrency = 2048
	}
	if o.Timeout <= 0 {
		o.Timeout = 800 * time.Millisecond
	}
	if o.Timeout > 10*time.Second {
		o.Timeout = 10 * time.Second
	}
	return o
}

// OpenPort 一个开放端口。
type OpenPort struct {
	Port    int           `json:"port"`
	Latency time.Duration `json:"latency_ms"`
}

// ScanTCPResult 单主机 TCP 扫描结果。
type ScanTCPResult struct {
	IP      string     `json:"ip"`
	Ports   []OpenPort `json:"ports"`
	Scanned int        `json:"scanned"`
	Elapsed string     `json:"elapsed"`
}

// ScanTCP 对单主机做 TCP connect 扫描，返回开放端口（升序）。
// 扫描本身不区分 closed / filtered：两者在用户态都表现为"连不上"，
// 内网盘点只关心 open，不做状态推断以免给出错误结论。
func (s *Scanner) ScanTCP(ctx context.Context, ip string, ports []int, opt ScanOptions) (*ScanTCPResult, error) {
	opt = opt.normalize()
	start := s.NowFunc()
	res := &ScanTCPResult{IP: ip, Scanned: len(ports)}

	if len(ports) == 0 {
		res.Elapsed = time.Since(start).Round(time.Millisecond).String()
		return res, nil
	}

	lim := s.limiterFor(opt.RatePPS)
	var mu sync.Mutex
	open := make([]OpenPort, 0, 8)

	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := opt.Concurrency
	if workers > len(ports) {
		workers = len(ports)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ctx.Err() != nil {
					return
				}
				if !lim.wait(func() bool { return ctx.Err() != nil }) {
					return
				}
				t0 := s.NowFunc()
				conn, err := s.dialTCP(ctx, ip, port, opt.Timeout)
				if err != nil {
					continue
				}
				lat := s.nowSince(t0)
				_ = conn.Close()
				mu.Lock()
				open = append(open, OpenPort{Port: port, Latency: lat})
				mu.Unlock()
			}
		}()
	}

feed:
	for _, p := range ports {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	res.Ports = open
	res.Elapsed = s.nowSince(start).String()
	return res, ctx.Err()
}

// dialTCP 单端口握手（可注入，便于测试）。
func (s *Scanner) dialTCP(ctx context.Context, ip string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ip, itoa(port))
	if s.dial != nil {
		return s.dial(ctx, "tcp", addr, timeout)
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// limiterFor 返回速控器：pps<=0 时用 Scanner 的默认限速（默认 800 pps）。
func (s *Scanner) limiterFor(pps int) *limiter {
	if pps > 0 {
		return newLimiter(pps)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limit == nil {
		s.limit = newLimiter(s.defaultRate)
	}
	return s.limit
}

// SetRate 设置默认速率上限（pps）。0 表示不限速——只在确认过网络质量后使用。
func (s *Scanner) SetRate(pps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultRate = pps
	s.limit = nil
}

// nowSince 返回自 t0 起的时长（可注入时钟时也成立）。
func (s *Scanner) nowSince(t0 time.Time) time.Duration {
	d := s.NowFunc().Sub(t0)
	if d < 0 {
		return 0
	}
	return d.Round(time.Microsecond)
}

// itoa 小工具：避免为一次转换引入 strconv 的字符串分配开销（端口转换在内层循环里）。
func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
