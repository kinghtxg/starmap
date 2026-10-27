package auth

import (
	"net"
	"sync"
	"time"
)

// 本地账号登录的失败限流。
//
// 为什么必须有：本地账号是最常被部署的认证方式，而内网环境的密码强度普遍偏弱
// （甚至就是文档里的示例密码）。没有限流时，一个脚本每秒可以尝试上千个口令，
// 而且 bcrypt 是故意设计成"慢"的——攻击者每发一次请求就让服务端烧掉一次 CPU，
// 这既是口令爆破入口，也是一个单请求就能触发的 CPU 放大攻击。
//
// 双层计数：
//  1. 按「IP + 用户名」：5 次失败锁 5 分钟 —— 拦住针对某个账号的定向爆破；
//  2. 按「IP」：20 次失败锁 15 分钟 —— 拦住"换着用户名扫"的密码喷洒。
//
// 回环地址（127.0.0.1 / ::1）只做第 1 层：部署在 nginx / SLB 后面且没配
// trusted_proxies 时，所有请求的来源都是反代地址，做第 2 层会把全部用户一起锁死。
// 这种情况下第 1 层仍然生效（定向爆破照样被拦住），并应在文档里提示配置 trusted_proxies。
const (
	loginFailWindow  = 10 * time.Minute // 失败计数的滑动窗口
	loginUserMaxFail = 5                // 同一 IP+用户名 允许的失败次数
	loginIPMaxFail   = 20               // 同一 IP 允许的失败次数
	loginUserLock    = 5 * time.Minute  // 超限后锁定时长
	loginIPLock      = 15 * time.Minute // IP 维度超限后的锁定时长
	maxLimiterKeys   = 4096             // 计数表上限，超过则先清理过期项
)

type failRecord struct {
	count int
	first time.Time // 窗口起点
	until time.Time // 锁定截止时间（零值表示未锁）
}

// loginLimiter 登录失败计数器（内存态，重启即清）。
type loginLimiter struct {
	mu   sync.Mutex
	byIP map[string]*failRecord
	byU  map[string]*failRecord
	now  func() time.Time // 可注入时钟（测试用）
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		byIP: map[string]*failRecord{},
		byU:  map[string]*failRecord{},
		now:  time.Now,
	}
}

// Allow 判断本次登录尝试是否放行。不放行时返回还需等待的秒数。
func (l *loginLimiter) Allow(ip, user string) (bool, int) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	// IP 维度（回环地址跳过：反代部署下所有请求来源相同，锁了等于全员锁死）
	if !isLoopback(ip) {
		if r := l.byIP[ip]; r != nil && now.Before(r.until) {
			return false, int(r.until.Sub(now).Seconds()) + 1
		}
	}
	if r := l.byU[ip+"|"+user]; r != nil && now.Before(r.until) {
		return false, int(r.until.Sub(now).Seconds()) + 1
	}
	return true, 0
}

// Fail 记录一次失败。
func (l *loginLimiter) Fail(ip, user string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	if !isLoopback(ip) {
		l.byIP[ip] = bump(l.byIP[ip], now, loginFailWindow, loginIPMaxFail, loginIPLock)
	}
	l.byU[ip+"|"+user] = bump(l.byU[ip+"|"+user], now, loginFailWindow, loginUserMaxFail, loginUserLock)

	// 防止被"每次换一个用户名"撑爆内存：只清过期项，不清仍生效的锁定
	if len(l.byIP)+len(l.byU) > maxLimiterKeys {
		l.pruneLocked(now)
	}
}

// Succeed 登录成功后清掉该用户的计数。
// IP 计数只减半而不是清零：否则攻击者只要蒙对一次就能把喷洒计数归零。
func (l *loginLimiter) Succeed(ip, user string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byU, ip+"|"+user)
	if r := l.byIP[ip]; r != nil {
		r.count /= 2
		if r.count == 0 {
			delete(l.byIP, ip)
		}
	}
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	alive := func(r *failRecord) bool {
		return now.Before(r.until) || now.Sub(r.first) < loginFailWindow
	}
	for k, r := range l.byIP {
		if !alive(r) {
			delete(l.byIP, k)
		}
	}
	for k, r := range l.byU {
		if !alive(r) {
			delete(l.byU, k)
		}
	}
}

// bump 累加失败计数，必要时打进锁定，并按窗口重置。
func bump(r *failRecord, now time.Time, window time.Duration, max int, lock time.Duration) *failRecord {
	if r == nil || now.Sub(r.first) > window {
		r = &failRecord{count: 0, first: now}
	}
	r.count++
	if r.count >= max {
		r.until = now.Add(lock)
		r.count = 0
		r.first = now
	}
	return r
}

func isLoopback(ip string) bool {
	if ip == "localhost" {
		return true
	}
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}
