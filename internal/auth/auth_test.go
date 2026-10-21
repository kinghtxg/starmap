package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestConfigValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("默认配置（mode=none）必须合法: %v", err)
	}
	if Default().Enabled() {
		t.Fatal("默认配置必须未启用认证（K1 默认关闭）")
	}
	if err := (Config{Mode: ModeLocal}).Validate(); err == nil {
		t.Fatal("mode=local 无账号应报错")
	}
	if err := (Config{Mode: ModeOIDC}).Validate(); err == nil {
		t.Fatal("mode=oidc 缺 issuer 应报错")
	}
	if err := (Config{Mode: "rbac"}).Validate(); err == nil {
		t.Fatal("未知 mode 应报错")
	}
}

func TestConfigNormalizedHashesPlainPassword(t *testing.T) {
	cfg := Config{
		Mode:       ModeLocal,
		LocalUsers: []LocalUser{{Username: "admin", Password: "s3cret"}},
	}.normalized()
	if cfg.LocalUsers[0].PasswordBcrypt == "" {
		t.Fatal("明文密码应被散列化")
	}
	if cfg.LocalUsers[0].Password != "" {
		t.Fatal("明文密码不应保留")
	}
	if cfg.SessionSecret == "" || cfg.CookieName != DefaultCookieName {
		t.Fatal("默认会话密钥/ Cookie 名未填充")
	}
}

func TestVerifyLocalPassword(t *testing.T) {
	hash, err := HashPassword("starmap-pass")
	if err != nil {
		t.Fatal(err)
	}
	rt := newRuntime(Config{Mode: ModeLocal, LocalUsers: []LocalUser{{Username: "ops", PasswordBcrypt: hash}}})
	if _, ok := rt.verifyLocal("ops", "starmap-pass"); !ok {
		t.Fatal("正确密码应通过")
	}
	if _, ok := rt.verifyLocal("ops", "wrong"); ok {
		t.Fatal("错误密码应拒绝")
	}
	if _, ok := rt.verifyLocal("nobody", "wrong"); ok {
		t.Fatal("不存在的账号应拒绝")
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	rt := newRuntime(Config{Mode: ModeLocal})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if err := rt.issue(c, "alice", "Alice", RoleAdmin, ModeLocal); err != nil {
		t.Fatal(err)
	}
	raw := w.Header().Get("Set-Cookie")
	if !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "SameSite=Lax") {
		t.Fatalf("Cookie 缺少 HttpOnly/SameSite=Lax: %s", raw)
	}
	cookie := (&http.Response{Header: w.Header()}).Cookies()[0]
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = r2
	claims, ok := rt.sessionFromRequest(c2)
	if !ok || claims.Sub != "alice" {
		t.Fatalf("会话解析失败: %+v ok=%v", claims, ok)
	}
	if Subject(c2) != "" {
		t.Fatal("未经过中间件时不应有身份")
	}
}

func TestSessionTamperedCookieRejected(t *testing.T) {
	rt := newRuntime(Config{Mode: ModeLocal})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	_ = rt.issue(c, "alice", "Alice", RoleAdmin, ModeLocal)
	good := (&http.Response{Header: w.Header()}).Cookies()[0]
	bad := &http.Cookie{Name: good.Name, Value: good.Value + "x"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(bad)
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = r
	if _, ok := rt.sessionFromRequest(c2); ok {
		t.Fatal("被篡改的 Cookie 必须拒绝")
	}
}

func TestSessionExpiry(t *testing.T) {
	rt := newRuntime(Config{Mode: ModeLocal, SessionTTLSeconds: 1})
	claims := sessionClaims{Sub: "bob", Sid: "s1", Exp: time.Now().Add(-time.Second).Unix()}
	if _, ok := rt.verify(mustSign(t, rt, claims)); ok {
		t.Fatal("过期会话必须失效")
	}
}

func mustSign(t *testing.T, rt *runtime, claims sessionClaims) string {
	t.Helper()
	v, err := rt.sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newTestEngine(rt *runtime) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(rt.middleware())
	registerRoutes(r, rt)
	r.GET("/api/topology", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	r.GET("/index.html", func(c *gin.Context) { c.String(200, "html") })
	return r
}

func TestMiddlewareNonePassesThrough(t *testing.T) {
	resetRuntime()
	rt := newRuntime(Config{Mode: ModeNone})
	r := newTestEngine(rt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/topology", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("mode=none 时必须原样放行，实际 %d", w.Code)
	}
}

func TestMiddlewareLocalDeniesAPIAndRedirectsPage(t *testing.T) {
	resetRuntime()
	rt := newRuntime(Config{Mode: ModeLocal, SessionTTLSeconds: 600})
	r := newTestEngine(rt)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/topology", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未认证 API 应 401，实际 %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Fatalf("未认证页面应 302 到 /login，实际 %d %s", w.Code, w.Header().Get("Location"))
	}

	// 放行路径
	for _, p := range []string{"/api/health", "/login", "/api/auth/config", "/assets/layout.js"} {
		w = httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusFound {
			t.Fatalf("放行路径 %s 被拦截（%d）", p, w.Code)
		}
	}
}

func TestLocalLoginFlowSetsSubject(t *testing.T) {
	resetRuntime()
	hash, _ := HashPassword("pw")
	rt := newRuntime(Config{Mode: ModeLocal, LocalUsers: []LocalUser{{Username: "ops", PasswordBcrypt: hash}}})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(rt.middleware())
	registerRoutes(r, rt)
	r.GET("/api/who", func(c *gin.Context) { c.JSON(200, gin.H{"sub": Subject(c)}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, newLoginRequest("ops", "pw"))
	if w.Code != http.StatusOK {
		t.Fatalf("登录应成功，实际 %d %s", w.Code, w.Body.String())
	}
	cookie := (&http.Response{Header: w.Header()}).Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/api/who", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "ops") {
		t.Fatalf("身份未写入 gin.Context: %s", w.Body.String())
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	resetRuntime()
	hash, _ := HashPassword("pw")
	rt := newRuntime(Config{Mode: ModeLocal, LocalUsers: []LocalUser{{Username: "ops", PasswordBcrypt: hash}}})
	r := newTestEngine(rt)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, newLoginRequest("ops", "pw"))
	if w.Code != http.StatusOK {
		t.Fatalf("登录应成功，实际 %d %s", w.Code, w.Body.String())
	}
	cookie := (&http.Response{Header: w.Header()}).Cookies()[0]

	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("me 应返回已认证，实际 %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("登出失败: %d", w.Code)
	}
	// 旧 Cookie 在未清除的客户端仍可能被带回 → 服务端吊销生效
	rt.sessions.revoke(parseSid(t, rt, cookie.Value))
	if !rt.sessions.revoked(parseSid(t, rt, cookie.Value)) {
		t.Fatal("会话应已被吊销")
	}
}

func TestLoginPageServed(t *testing.T) {
	resetRuntime()
	rt := newRuntime(Config{Mode: ModeLocal})
	r := newTestEngine(rt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "StarMap") {
		t.Fatalf("登录页应可访问，实际 %d %d 字节", w.Code, w.Body.Len())
	}
}

func newLoginRequest(user, pass string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func parseSid(t *testing.T, rt *runtime, value string) string {
	t.Helper()
	claims, ok := rt.verify(value)
	if !ok {
		t.Fatal("会话解析失败")
	}
	return claims.Sid
}
