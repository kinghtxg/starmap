package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 会话签发/校验是整套鉴权的信任根：
// 一旦 verify 能被绕过，角色门禁、审计归属、吊销全部失效。
// 这里只碰 newRuntime 产出的独立实例，不碰进程级单例（单例会缓存首个 cfg，
// 后续用例改 CookieName 之类不会生效，测出来的东西是假的）。

func sessionRT(t *testing.T, cfg Config) *runtime {
	t.Helper()
	if cfg.Mode == "" {
		cfg.Mode = ModeLocal
	}
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = "unit-test-secret-0123456789abcdef"
	}
	rt := newRuntime(cfg)
	if rt.cfg.SessionSecret != cfg.SessionSecret {
		t.Fatalf("会话密钥未生效: %q", rt.cfg.SessionSecret)
	}
	return rt
}

func liveClaims(sub string) sessionClaims {
	now := time.Now()
	return sessionClaims{
		Sub:  sub,
		Name: sub,
		Role: RoleAdmin,
		Via:  "local",
		Sid:  "sid-" + sub,
		Iat:  now.Unix(),
		Exp:  now.Add(time.Hour).Unix(),
	}
}

// TestSignVerifyRoundtrip 自签令牌必须原样解回，且角色/来源不丢。
func TestSignVerifyRoundtrip(t *testing.T) {
	rt := sessionRT(t, Config{})
	in := liveClaims("alice")
	tok, err := rt.sign(in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, ok := rt.verify(tok)
	if !ok {
		t.Fatal("自签的令牌应校验通过")
	}
	if out.Sub != in.Sub || out.Role != in.Role || out.Via != in.Via || out.Sid != in.Sid {
		t.Fatalf("载荷不符: %+v", out)
	}
}

// TestVerifyRejectsTampered 篡改载荷、篡改签名、换密钥、垃圾串一律拒绝。
// 这是「角色随 Cookie 走」的安全前提：能改载荷就等于能自封 admin。
func TestVerifyRejectsTampered(t *testing.T) {
	rt := sessionRT(t, Config{})
	tok, err := rt.sign(liveClaims("alice"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	dot := -1
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(tok)-1 {
		t.Fatalf("令牌不是 payload.sig 形式: %q", tok)
	}
	payload, sig := tok[:dot], tok[dot+1:]

	cases := map[string]string{
		"载荷末位被改":      flipTail(payload) + "." + sig,
		"载荷加料":        payload + "A" + "." + sig,
		"签名被改":        payload + "." + flipTail(sig),
		"签名截断":        payload + "." + sig[:len(sig)-2],
		"没有签名":        payload,
		"空串":          "",
		"只有点":         ".",
		"点结尾":         payload + ".",
		"垃圾串":         "garbage",
		"payload非b64": "!!!." + sig,
	}
	for name, bad := range cases {
		if _, ok := rt.verify(bad); ok {
			t.Fatalf("%s 仍通过校验", name)
		}
	}

	// 换一个密钥的实例：签名对不上，必须拒绝（会话不能跨部署漂移）
	other := sessionRT(t, Config{SessionSecret: "another-secret-0123456789abcdef"})
	if _, ok := other.verify(tok); ok {
		t.Fatal("不同会话密钥签发的令牌不应通用")
	}
}

func flipTail(s string) string {
	if s == "" {
		return "A"
	}
	if s[len(s)-1] == 'A' {
		return s[:len(s)-1] + "B"
	}
	return s[:len(s)-1] + "A"
}

// TestClaimsValid 有效性判定的边界：无身份或过期都算无效。
func TestClaimsValid(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name   string
		claims sessionClaims
		want   bool
	}{
		{"正常", sessionClaims{Sub: "a", Exp: now + 60}, true},
		{"无身份", sessionClaims{Exp: now + 60}, false},
		{"已过期", sessionClaims{Sub: "a", Exp: now - 1}, false},
		{"无有效期", sessionClaims{Sub: "a"}, false},
		{"恰好到期", sessionClaims{Sub: "a", Exp: now}, false},
	}
	for _, c := range cases {
		if got := c.claims.valid(); got != c.want {
			t.Fatalf("%s: valid()=%v 期望 %v", c.name, got, c.want)
		}
	}
}

// TestIssueWritesSecureCookie 签发的 Cookie 必须 HttpOnly + SameSite=Lax，
// 且 MaxAge 与 session_ttl 一致（TTL 写在两个地方，容易只改一处）。
func TestIssueWritesSecureCookie(t *testing.T) {
	rt := sessionRT(t, Config{SessionTTLSeconds: 120, CookieName: "sm_unit"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	if err := rt.issue(c, "carol", "", "operator", ModeLocal); err != nil {
		t.Fatalf("issue: %v", err)
	}
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("应恰好写入 1 个 Cookie，实际 %d 个", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != "sm_unit" {
		t.Fatalf("Cookie 名应为 sm_unit，实际 %q", ck.Name)
	}
	if !ck.HttpOnly {
		t.Fatal("会话 Cookie 必须 HttpOnly（防 XSS 窃取）")
	}
	if ck.SameSite != http.SameSiteLaxMode {
		t.Fatal("会话 Cookie 必须 SameSite=Lax")
	}
	if ck.MaxAge != 120 {
		t.Fatalf("MaxAge 应等于 session_ttl(120)，实际 %d", ck.MaxAge)
	}

	claims, ok := rt.verify(ck.Value)
	if !ok {
		t.Fatal("签发的 Cookie 应能自校验")
	}
	if claims.Name != "carol" {
		t.Fatalf("未给展示名时应回落为用户名，实际 %q", claims.Name)
	}
	if claims.Role != RoleOperator {
		t.Fatalf("角色应为 operator，实际 %q", claims.Role)
	}
	if claims.Sid == "" {
		t.Fatal("缺少会话 ID，吊销功能会失效")
	}
}

// TestIssueNormalizesRole 非标准角色不落进 Cookie，避免"自封 admin"。
func TestIssueNormalizesRole(t *testing.T) {
	rt := sessionRT(t, Config{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if err := rt.issue(c, "x", "X", "root", ModeLocal); err != nil {
		t.Fatalf("issue: %v", err)
	}
	ck := (&http.Response{Header: w.Header()}).Cookies()[0]
	claims, ok := rt.verify(ck.Value)
	if !ok {
		t.Fatal("Cookie 应可校验")
	}
	if claims.Role != "" {
		t.Fatalf("非标准角色应被清空，实际 %q", claims.Role)
	}
}

// TestSessionFromRequestHonoursRevocation 服务端吊销必须压过客户端 Cookie：
// 登出后浏览器就算把旧 Cookie 带回来也不能复活。
func TestSessionFromRequestHonoursRevocation(t *testing.T) {
	rt := sessionRT(t, Config{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if err := rt.issue(c, "dave", "Dave", RoleViewer, ModeLocal); err != nil {
		t.Fatalf("issue: %v", err)
	}
	ck := (&http.Response{Header: w.Header()}).Cookies()[0]

	withCookie := func() (*gin.Context, *httptest.ResponseRecorder) {
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(ck)
		c2.Request = req
		return c2, w2
	}

	c2, _ := withCookie()
	claims, ok := rt.sessionFromRequest(c2)
	if !ok || claims.Sub != "dave" || claims.Role != RoleViewer {
		t.Fatalf("未能从 Cookie 还原身份: %+v ok=%v", claims, ok)
	}

	c4, w4 := withCookie()
	rt.revoke(c4)
	if !rt.sessions.revoked(claims.Sid) {
		t.Fatal("撤销后会话应标记为已吊销")
	}

	c5, _ := withCookie()
	if _, ok := rt.sessionFromRequest(c5); ok {
		t.Fatal("已吊销会话必须拒绝")
	}

	cleared := (&http.Response{Header: w4.Header()}).Cookies()
	if len(cleared) == 0 {
		t.Fatal("撤销应清除客户端 Cookie")
	}
	last := cleared[len(cleared)-1]
	if last.MaxAge >= 0 || last.Value != "" {
		t.Fatalf("撤销未清 Cookie: %+v", last)
	}
	if !last.HttpOnly {
		t.Fatal("清除 Cookie 时也应保持 HttpOnly 属性（否则部分浏览器不会覆盖）")
	}
}

// TestSessionStoreSweep 会话表必须随过期回收，否则长期在线会缓慢泄漏。
func TestSessionStoreSweep(t *testing.T) {
	s := newSessionStore()
	now := time.Now()
	s.put(&sessionRecord{Sid: "old", Expiry: now.Add(-time.Minute)})
	s.put(&sessionRecord{Sid: "new", Expiry: now.Add(time.Hour)})

	s.mu.Lock()
	total := len(s.m)
	_, hasOld := s.m["old"]
	s.mu.Unlock()
	if total != 1 || hasOld {
		t.Fatalf("过期会话未被回收: 总 %d 条, 仍含 old=%v", total, hasOld)
	}
	// 不存在的 sid 视为未吊销，且 revoke 不应 panic
	if s.revoked("absent") {
		t.Fatal("不存在的会话不应报已吊销")
	}
	s.revoke("absent")
	if s.revoked("new") {
		t.Fatal("未吊销的会话不应报已吊销")
	}
	s.revoke("new")
	if !s.revoked("new") {
		t.Fatal("吊销未生效")
	}
}

// TestSessionFromRequestNoCookie 没有 Cookie 时安静返回 false，不 panic。
func TestSessionFromRequestNoCookie(t *testing.T) {
	rt := sessionRT(t, Config{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := rt.sessionFromRequest(c); ok {
		t.Fatal("无 Cookie 不应返回会话")
	}

	// 有 Cookie 名但值为空（浏览器清空但未删）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: rt.cfg.CookieName, Value: ""})
	c.Request = req
	if _, ok := rt.sessionFromRequest(c); ok {
		t.Fatal("空 Cookie 不应返回会话")
	}
}
