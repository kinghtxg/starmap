package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// runtime 是进程内唯一的认证运行时：持有规范化后的配置、会话表、
// OIDC 流程状态（state/PKCE verifier）与身份服务客户端。
type runtime struct {
	cfg      Config
	sessions *sessionStore
	flows    *flowStore
	oidc     *oidcClient
	login    *loginLimiter
}

func newRuntime(cfg Config) *runtime {
	c := cfg.normalized()
	return &runtime{
		cfg:      c,
		sessions: newSessionStore(),
		flows:    newFlowStore(),
		oidc:     newOIDCClient(c.OIDC),
		login:    newLoginLimiter(),
	}
}

// 进程级单例：Middleware(cfg) 与 RegisterRoutes(r, cfg) 必须共享同一份
// 流程状态与会话表，否则 OIDC 回调找不到签发时的 state/PKCE verifier。
var (
	rtMu        sync.Mutex
	rtSingleton *runtime
)

func shared(cfg Config) *runtime {
	rtMu.Lock()
	defer rtMu.Unlock()
	if rtSingleton == nil {
		rtSingleton = newRuntime(cfg)
	}
	return rtSingleton
}

// resetRuntime 仅用于测试：丢弃进程级单例。
func resetRuntime() {
	rtMu.Lock()
	rtSingleton = nil
	rtMu.Unlock()
}

// ---------- 会话表（内存，重启即失；仅用于吊销与展示，不落库） ----------

type sessionRecord struct {
	Sid      string
	Sub      string
	Name     string
	Via      string // local | oidc
	Expiry   time.Time
	Revoked  bool
	IssuedAt time.Time
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]*sessionRecord
}

func newSessionStore() *sessionStore { return &sessionStore{m: map[string]*sessionRecord{}} }

func (s *sessionStore) put(r *sessionRecord) {
	s.mu.Lock()
	s.sweepLocked(time.Now())
	s.m[r.Sid] = r
	s.mu.Unlock()
}

func (s *sessionStore) revoked(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[sid]
	return ok && r.Revoked
}

func (s *sessionStore) revoke(sid string) {
	s.mu.Lock()
	if r, ok := s.m[sid]; ok {
		r.Revoked = true
	}
	s.mu.Unlock()
}

func (s *sessionStore) sweepLocked(now time.Time) {
	for k, r := range s.m {
		if r.Expiry.Before(now) {
			delete(s.m, k)
		}
	}
}

// ---------- OIDC 流程状态（state → PKCE verifier / 回跳地址） ----------

type flowRecord struct {
	State    string
	Verifier string // PKCE code_verifier
	Next     string // 登录成功后回跳（仅允许本站相对路径）
	Expiry   time.Time
}

type flowStore struct {
	mu sync.Mutex
	m  map[string]*flowRecord
}

func newFlowStore() *flowStore { return &flowStore{m: map[string]*flowRecord{}} }

func (s *flowStore) put(r *flowRecord) {
	s.mu.Lock()
	now := time.Now()
	for k, v := range s.m {
		if v.Expiry.Before(now) {
			delete(s.m, k)
		}
	}
	s.m[r.State] = r
	s.mu.Unlock()
}

// take 取出并立即删除（一次性使用）。
func (s *flowStore) take(state string) (*flowRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[state]
	if ok {
		delete(s.m, state)
	}
	return r, ok
}

// ---------- 随机串 ----------

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read 在 Go 运行时下不会失败；退化路径仍保证返回值非空。
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}
