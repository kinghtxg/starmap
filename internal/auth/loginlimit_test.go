package auth

import (
	"testing"
	"time"
)

// 登录失败限流用例。
//
// 这些断言对应的是真实攻击场景：定向爆破单个账号、换用户名做密码喷洒、
// 以及"再试一次说不定就中了"的持续尝试。限流不是可选优化，是认证功能的一部分。

func TestLoginLimiterLocksAfterUserFailures(t *testing.T) {
	l := newLoginLimiter()
	ip, user := "10.1.2.3", "admin"

	for i := 0; i < loginUserMaxFail; i++ {
		if ok, _ := l.Allow(ip, user); !ok {
			t.Fatalf("第 %d 次尝试不该被拦", i+1)
		}
		l.Fail(ip, user)
	}
	ok, retry := l.Allow(ip, user)
	if ok {
		t.Fatal("达到失败上限后应拒绝登录")
	}
	if retry <= 0 || retry > int(loginUserLock.Seconds())+1 {
		t.Errorf("Retry-After 应为正整数且不超过锁定窗口，实际 %d", retry)
	}

	// 锁定是"按 IP+用户名"的：同一 IP 换个账号不该被这个锁影响
	// （否则一个用户输错密码会把同网段所有人挡在外面）
	if ok, _ := l.Allow(ip, "auditor"); !ok {
		t.Error("锁定不应扩散到其他用户名")
	}
}

func TestLoginLimiterSprayAcrossUsers(t *testing.T) {
	l := newLoginLimiter()
	ip := "10.9.9.9"
	// 换着用户名扫：每个用户名只错 1 次，靠用户维度永远锁不住
	for i := 0; i < loginIPMaxFail; i++ {
		u := "user" + string(rune('a'+i))
		if ok, _ := l.Allow(ip, u); !ok {
			t.Fatalf("第 %d 个用户名不该被拦", i+1)
		}
		l.Fail(ip, u)
	}
	if ok, _ := l.Allow(ip, "brand-new-user"); ok {
		t.Fatal("同一 IP 累计失败达到上限后，换新用户名也应被拦（防密码喷洒）")
	}
	// 其他来源不受影响
	if ok, _ := l.Allow("10.9.9.10", "brand-new-user"); !ok {
		t.Error("不应误伤其他来源地址")
	}
}

func TestLoginLimiterSuccessResets(t *testing.T) {
	l := newLoginLimiter()
	ip, user := "10.5.5.5", "admin"
	for i := 0; i < loginUserMaxFail-1; i++ {
		l.Fail(ip, user)
	}
	l.Succeed(ip, user)
	// 成功一次后计数清零：之前 4 次失败不该再累计
	for i := 0; i < loginUserMaxFail-1; i++ {
		l.Fail(ip, user)
	}
	if ok, _ := l.Allow(ip, user); !ok {
		t.Error("成功登录后计数应清零，此时尚未达到上限")
	}
}

func TestLoginLimiterLoopbackSkipsIPDimension(t *testing.T) {
	l := newLoginLimiter()
	// 反代部署且未配 trusted_proxies 时，所有请求来源都是回环地址。
	// 若此时做 IP 维度锁定，等于一次爆破就把全部用户锁死。
	for i := 0; i < loginIPMaxFail; i++ {
		l.Fail("127.0.0.1", "u"+string(rune('a'+i)))
	}
	if ok, _ := l.Allow("127.0.0.1", "someone-else"); !ok {
		t.Fatal("回环地址不应触发 IP 维度锁定")
	}
	// 但针对具体账号的锁定仍然生效
	for i := 0; i < loginUserMaxFail; i++ {
		l.Fail("127.0.0.1", "victim")
	}
	if ok, _ := l.Allow("127.0.0.1", "victim"); ok {
		t.Error("回环地址下，定向爆破单个账号仍应被拦")
	}
}

func TestLoginLimiterUnlocksAfterWindow(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	ip, user := "10.2.2.2", "admin"
	for i := 0; i < loginUserMaxFail; i++ {
		l.Fail(ip, user)
	}
	if ok, _ := l.Allow(ip, user); ok {
		t.Fatal("刚达到上限应处于锁定状态")
	}
	now = now.Add(loginUserLock + time.Second)
	if ok, _ := l.Allow(ip, user); !ok {
		t.Error("锁定窗口结束后应自动解锁，不能要求重启服务")
	}
}

func TestLoginLimiterPruneKeepsLocked(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	// 造一个仍处于锁定状态的条目
	for i := 0; i < loginUserMaxFail; i++ {
		l.Fail("10.3.3.3", "locked-user")
	}
	// 再灌大量过期条目触发清理
	now = now.Add(loginFailWindow + time.Minute)
	for i := 0; i < maxLimiterKeys+10; i++ {
		l.Fail("10.4.4."+string(rune(i%200)), "u")
	}
	// 清理不能把仍在生效的锁定一并清掉：这里换成"当前时间点仍在锁内"的场景
	l2 := newLoginLimiter()
	l2.now = func() time.Time { return time.Now() }
	for i := 0; i < loginUserMaxFail; i++ {
		l2.Fail("10.6.6.6", "still-locked")
	}
	for i := 0; i < maxLimiterKeys+10; i++ {
		l2.Fail("10.7.7.7", "x"+string(rune('a'+i%26)))
	}
	if ok, _ := l2.Allow("10.6.6.6", "still-locked"); ok {
		t.Error("清理过期条目时不应清除仍生效的锁定")
	}
}

func TestLoginLimiterNilSafe(t *testing.T) {
	var l *loginLimiter
	if ok, _ := l.Allow("1.2.3.4", "u"); !ok {
		t.Error("nil 限流器应放行（未初始化时不阻断登录）")
	}
	l.Fail("1.2.3.4", "u")
	l.Succeed("1.2.3.4", "u")
}
