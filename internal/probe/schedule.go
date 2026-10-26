package probe

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 主动发现的调度约束。
//
// 这一层看起来"不影响功能"，但决定了这套东西能不能在真实内网长期挂着跑：
//   - 没有时间窗口，全端口扫描可能正好撞上业务高峰，把 OA 卡死一次就再也没人敢开；
//   - 没有失败退避，一台已经下线的机器每轮都重扫 65535 个端口，白白吃掉速率预算，
//     让真正需要扫的新资产排到后面；
//   - 没有已知主机降频，几百台早就台账在册的服务器每轮都全端口重扫，纯属浪费。
//
// 三者都属于"不做也能演示、做了才能上线"的部分，所以放在编排层统一管。

// ErrOutsideWindow 当前不在允许扫描的时间窗口内。
var ErrOutsideWindow = errors.New("当前不在扫描时间窗口内")

// Window 扫描时间窗口（支持跨夜，如 22:00-06:00）。
type Window struct {
	StartMin int // 起始分钟（含）
	EndMin   int // 结束分钟（不含）
	spec     string
}

// ParseWindow 解析 "HH:MM-HH:MM"；空串表示全天允许。
// 起止相同（如 00:00-00:00）视为全天——这是运维最常用的"不限制"写法。
func ParseWindow(spec string) (Window, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return Window{spec: "全天"}, nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return Window{}, fmt.Errorf("时间窗口格式错误 %q：应为 HH:MM-HH:MM", spec)
	}
	start, err := parseClock(parts[0])
	if err != nil {
		return Window{}, fmt.Errorf("时间窗口起始时间非法 %q：%v", parts[0], err)
	}
	end, err := parseClock(parts[1])
	if err != nil {
		return Window{}, fmt.Errorf("时间窗口结束时间非法 %q：%v", parts[1], err)
	}
	return Window{StartMin: start, EndMin: end, spec: fmt.Sprintf("%02d:%02d-%02d:%02d", start/60, start%60, end/60, end%60)}, nil
}

func parseClock(s string) (int, error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, errors.New("缺少冒号")
	}
	h, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, errors.New("小时不是数字")
	}
	m, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, errors.New("分钟不是数字")
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, errors.New("时间超出 00:00-23:59")
	}
	return h*60 + m, nil
}

// Contains 判断某时刻是否允许扫描。
func (w Window) Contains(t time.Time) bool {
	if w.spec == "全天" || w.StartMin == w.EndMin {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	if w.StartMin < w.EndMin {
		return m >= w.StartMin && m < w.EndMin
	}
	// 跨夜窗口：22:00-06:00 → [22:00,24:00) ∪ [00:00,06:00)
	return m >= w.StartMin || m < w.EndMin
}

func (w Window) String() string {
	if w.spec == "" {
		return "全天"
	}
	return w.spec
}

// Backoff 失败退避：连续失败的探测定时重试，成功一次即清零。
//
// 为什么要按主机而不是全局退避：一台断电的机器会把整轮扫描拖慢，
// 但它旁边的资产仍在正常变化，全局退避等于让健康资产陪着一起停摆。
type Backoff struct {
	base  time.Duration
	max   time.Duration
	mu    sync.Mutex
	state map[string]*backoffEntry
}

type backoffEntry struct {
	fails int
	until time.Time
}

// NewBackoff 创建退避器；base<=0 用 1 分钟，max<=0 用 6 小时。
func NewBackoff(base, max time.Duration) *Backoff {
	if base <= 0 {
		base = time.Minute
	}
	if max <= 0 {
		max = 6 * time.Hour
	}
	if max < base {
		max = base
	}
	return &Backoff{base: base, max: max, state: make(map[string]*backoffEntry)}
}

// Fail 记录一次失败，返回本次退避时长。
func (b *Backoff) Fail(ip string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == nil {
		b.state = make(map[string]*backoffEntry)
	}
	e := b.state[ip]
	if e == nil {
		e = &backoffEntry{}
		b.state[ip] = e
	}
	e.fails++
	d := b.delayFor(e.fails)
	e.until = now.Add(d)
	return d
}

// Succeed 记录一次成功：清除退避状态。
func (b *Backoff) Succeed(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.state, ip)
}

// Due 判断该主机现在是否可以再扫。
func (b *Backoff) Due(ip string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.state[ip]
	if e == nil {
		return true
	}
	return !now.Before(e.until)
}

// Fails 返回连续失败次数（用于日志与界面展示）。
func (b *Backoff) Fails(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.state[ip]; e != nil {
		return e.fails
	}
	return 0
}

// NextRetry 返回下次允许扫描的时刻；无退避状态时返回零值。
func (b *Backoff) NextRetry(ip string) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.state[ip]; e != nil {
		return e.until
	}
	return time.Time{}
}

// delayFor 指数退避：base * 2^(fails-1)，上限 max。
func (b *Backoff) delayFor(fails int) time.Duration {
	if fails < 1 {
		return 0
	}
	d := b.base
	for i := 1; i < fails; i++ {
		d *= 2
		if d >= b.max {
			return b.max
		}
	}
	if d > b.max {
		d = b.max
	}
	return d
}
