package auth

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/web"
)

// RegisterRoutes 注册登录相关路由。
// 与 Middleware(cfg) 配套使用：二者共享同一进程级运行时。
//
//	GET  /login                  登录页（web/login.html）
//	GET  /api/auth/config        当前认证模式（供前端决定显示表单还是 SSO 按钮）
//	POST /api/auth/login         本地账号登录（mode=local）
//	GET  /api/auth/oidc/start    发起 OIDC（APSSO）登录（state + PKCE）
//	GET  /api/auth/callback      OIDC 回调
//	POST /api/auth/logout        登出
//	GET  /api/auth/me            当前身份
func RegisterRoutes(r gin.IRouter, cfg Config) {
	registerRoutes(r, shared(cfg))
}

func registerRoutes(r gin.IRouter, rt *runtime) {
	if !rt.cfg.Enabled() {
		// K1：未启用时只暴露一个只读的模式查询端点，行为与 V1.0 一致。
		r.GET("/api/auth/config", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"mode": ModeNone, "enabled": false})
		})
		return
	}
	r.GET("/login", loginPage(rt))
	g := r.Group("/api/auth")
	{
		g.GET("/config", authConfig(rt))
		g.POST("/login", localLogin(rt))
		g.GET("/oidc/start", oidcStart(rt))
		g.GET("/callback", oidcCallback(rt))
		g.POST("/logout", logout(rt))
		g.GET("/me", me(rt))
	}
}

// loginPage 返回登录页（内嵌静态资源，无 CDN）。
func loginPage(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := web.FS.ReadFile("login.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "登录页缺失")
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}
}

// authConfig 供前端决定展示形态。
func authConfig(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		body := gin.H{
			"mode":    rt.cfg.Mode,
			"enabled": true,
			"ttl":     rt.cfg.SessionTTLSeconds,
		}
		if rt.cfg.Mode == ModeOIDC {
			body["provider_name"] = rt.cfg.OIDC.ProviderName
			body["oidc_start"] = "/api/auth/oidc/start"
		}
		if rt.cfg.Mode == ModeLocal {
			body["local"] = true
		}
		c.JSON(http.StatusOK, body)
	}
}

// localLogin 本地账号登录（bcrypt 校验）。
func localLogin(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rt.cfg.Mode != ModeLocal {
			failJSON(c, http.StatusBadRequest, "当前认证模式不是 local")
			return
		}
		if !sameOrigin(c) {
			failJSON(c, http.StatusForbidden, "跨站请求已拒绝")
			return
		}
		var req struct {
			Username string `json:"username" form:"username"`
			Password string `json:"password" form:"password"`
		}
		if err := c.ShouldBind(&req); err != nil {
			failJSON(c, http.StatusBadRequest, "请求格式错误")
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			failJSON(c, http.StatusBadRequest, "用户名或密码不能为空")
			return
		}
		u, ok := rt.verifyLocal(req.Username, req.Password)
		if !ok {
			failJSON(c, http.StatusUnauthorized, "用户名或密码错误")
			return
		}
		name := u.DisplayName
		if name == "" {
			name = u.Username
		}
		if err := rt.issue(c, u.Username, name, ModeLocal); err != nil {
			failJSON(c, http.StatusInternalServerError, "会话签发失败")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "subject": u.Username, "display_name": name})
	}
}

// oidcStart 生成 state + PKCE verifier 后跳转到 APSSO 授权端点。
func oidcStart(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rt.cfg.Mode != ModeOIDC {
			errorPage(c, http.StatusBadRequest, "未启用 OIDC", "当前 auth.mode 不是 oidc")
			return
		}
		state := randomHex(16)
		verifier := randomHex(32)
		rt.flows.put(&flowRecord{
			State:    state,
			Verifier: verifier,
			Next:     safeNext(c.Query(returnToParam)),
			Expiry:   time.Now().Add(stateCookieTTL * time.Second),
		})
		setCookie(c.Writer, &http.Cookie{
			Name:     stateCookieName,
			Value:    state,
			Path:     "/",
			MaxAge:   stateCookieTTL,
			HttpOnly: true,
			Secure:   rt.cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		redirectURI := rt.redirectURI(c)
		target, err := rt.authorizeURL(c.Request.Context(), redirectURI, state, verifier)
		if err != nil {
			// §7.5 降级：身份服务不可达 → 503，绝不静默放行。
			errorPage(c, http.StatusServiceUnavailable, "身份服务不可达", err.Error())
			return
		}
		c.Redirect(http.StatusFound, target)
	}
}

// oidcCallback 校验 state、用 code+verifier 换令牌、校验 ID Token 后签发会话。
func oidcCallback(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rt.cfg.Mode != ModeOIDC {
			errorPage(c, http.StatusBadRequest, "未启用 OIDC", "当前 auth.mode 不是 oidc")
			return
		}
		if desc := c.Query("error"); desc != "" {
			errorPage(c, http.StatusBadGateway, "身份服务拒绝了本次登录",
				desc+" "+c.Query("error_description"))
			return
		}
		code := c.Query("code")
		state := c.Query("state")
		if code == "" || state == "" {
			errorPage(c, http.StatusBadRequest, "回调参数不完整", "缺少 code 或 state")
			return
		}
		want, err := c.Cookie(stateCookieName)
		if err != nil || want == "" {
			errorPage(c, http.StatusBadRequest, "登录状态已失效", "请重新发起登录")
			return
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(state)) != 1 {
			errorPage(c, http.StatusBadRequest, "state 校验失败", "疑似跨站请求，已拒绝")
			return
		}
		// 清除 state Cookie（一次性）
		setCookie(c.Writer, &http.Cookie{
			Name:     stateCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   rt.cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		flow, ok := rt.flows.take(state)
		if !ok {
			errorPage(c, http.StatusBadRequest, "登录状态已过期", "请重新发起登录")
			return
		}
		tok, err := rt.exchange(c.Request.Context(), code, rt.redirectURI(c), flow.Verifier)
		if err != nil {
			errorPage(c, http.StatusServiceUnavailable, "身份服务不可达", err.Error())
			return
		}
		claims, err := rt.identify(c.Request.Context(), tok)
		if err != nil {
			errorPage(c, http.StatusServiceUnavailable, "身份校验失败", err.Error())
			return
		}
		if err := rt.issue(c, claims.Sub, claims.display(), ModeOIDC); err != nil {
			errorPage(c, http.StatusInternalServerError, "会话签发失败", err.Error())
			return
		}
		c.Redirect(http.StatusFound, flow.Next)
	}
}

// logout 吊销会话并清除 Cookie。
func logout(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sameOrigin(c) {
			failJSON(c, http.StatusForbidden, "跨站请求已拒绝")
			return
		}
		rt.revoke(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// me 返回当前身份；未认证返回 401。
func me(rt *runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := rt.sessionFromRequest(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"authenticated": false, "mode": rt.cfg.Mode})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"mode":          rt.cfg.Mode,
			"subject":       claims.Sub,
			"display_name":  claims.Name,
			"via":           claims.Via,
		})
	}
}

// redirectURI 回调地址：优先配置值，未配置时按当前请求推导（便于一键部署）。
func (r *runtime) redirectURI(c *gin.Context) string {
	if v := strings.TrimSpace(r.cfg.OIDC.RedirectURL); v != "" {
		return v
	}
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if p := c.GetHeader("X-Forwarded-Proto"); p != "" {
		scheme = strings.Split(p, ",")[0]
	}
	return scheme + "://" + c.Request.Host + "/api/auth/callback"
}

// safeNext 只接受本站相对路径，防开放重定向。
func safeNext(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, "\\") {
		return "/"
	}
	return v
}

// sameOrigin 校验 Origin（存在时必须与 Host 一致），防 CSRF。
func sameOrigin(c *gin.Context) bool {
	o := c.GetHeader("Origin")
	if o == "" {
		return true // 非浏览器客户端/同源表单
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, c.Request.Host)
}

func failJSON(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"error": msg})
}

// errorPage 面向浏览器的错误页（内网环境，无外部资源）。
func errorPage(c *gin.Context, code int, title, detail string) {
	body := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{background:#0F172A;color:#E2E8F0;font-family:system-ui,"Segoe UI","Microsoft YaHei",sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#1E293B;border:1px solid rgba(56,189,248,.25);border-radius:14px;padding:32px 36px;max-width:440px}
h1{font-size:18px;margin:0 0 12px;color:#F87171}p{margin:0 0 18px;color:#94A3B8;font-size:13px;line-height:1.7}
a{color:#38BDF8;text-decoration:none;font-size:14px}</style>
<div class="box"><h1>%s</h1><p>%s</p><a href="/login">返回登录页</a></div>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(detail))
	c.Data(code, "text/html; charset=utf-8", []byte(body))
}
