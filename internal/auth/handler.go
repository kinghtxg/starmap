package auth

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
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
		// K1：未启用时只暴露两个只读端点，行为与 V1.0 一致。
		r.GET("/api/auth/config", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"mode": ModeNone, "enabled": false})
		})
		// /api/auth/me 由本包独占（不要在 api 包里再注册一次，Gin 会对同一路径 panic）。
		// 未启用认证时恒为 admin：K1「零配置可用」的语义——本机就是最高权限。
		r.GET("/api/auth/me", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"authenticated": false,
				"mode":          ModeNone,
				"subject":       "",
				"display_name":  "本机管理员",
				"role":          RoleAdmin,
			})
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
		// 登录失败限流：本地账号是弱口令的重灾区，而 bcrypt 每次校验都要烧 CPU，
		// 不限制就等于给攻击者一个"每请求一次就算一次哈希"的放大器。
		ip := c.ClientIP()
		if ok, retry := rt.login.Allow(ip, req.Username); !ok {
			c.Header("Retry-After", strconv.Itoa(retry))
			failJSON(c, http.StatusTooManyRequests,
				"登录失败次数过多，请 "+strconv.Itoa(retry)+" 秒后再试")
			return
		}
		u, ok := rt.verifyLocal(req.Username, req.Password)
		if !ok {
			rt.login.Fail(ip, req.Username)
			failJSON(c, http.StatusUnauthorized, "用户名或密码错误")
			return
		}
		rt.login.Succeed(ip, req.Username)
		name := u.DisplayName
		if name == "" {
			name = u.Username
		}
		role := resolveLocalRole(u)
		if err := rt.issue(c, u.Username, name, role, ModeLocal); err != nil {
			failJSON(c, http.StatusInternalServerError, "会话签发失败")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ok": true, "subject": u.Username, "display_name": name, "role": role,
		})
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
		role := roleFromClaims(claims)
		if err := rt.issue(c, claims.Sub, claims.display(), role, ModeOIDC); err != nil {
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
			"role":          claims.Role,
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
// 视觉与刻本口径的登录页一致：浅色画布 + 白卡片 + 蓝色主按钮，不做深色另类风格。
func errorPage(c *gin.Context, code int, title, detail string) {
	body := fmt.Sprintf(`<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s · 星图</title>
<style>
:root{--accent:#3370ff;--canvas:#f6f7fa;--panel:#fff;--border:#e5e6e8;--text:#1f2329;--text-2:#646a73;--danger:#e64545;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background:var(--canvas);color:var(--text);font-family:var(--sans);font-size:14px;-webkit-font-smoothing:antialiased}
.box{width:100%%;max-width:440px;background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:32px;box-shadow:0 4px 16px rgba(31,35,41,.06)}
.mark{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.mark i{width:32px;height:32px;border-radius:8px;background:var(--accent);display:flex;align-items:center;
justify-content:center;color:#fff;font-style:normal;font-size:15px;font-weight:600}
.mark span{font-size:15px;font-weight:600}
h1{font-size:20px;line-height:1.4;margin:0 0 8px;font-weight:600;color:var(--danger)}
p{margin:0 0 24px;color:var(--text-2);font-size:13px;line-height:1.8;word-break:break-word}
a{display:inline-flex;align-items:center;height:34px;padding:0 16px;border-radius:6px;background:var(--accent);
color:#fff;text-decoration:none;font-size:13px;transition:background .12s}
a:hover{background:#2860e0}
</style>
<div class="box"><div class="mark"><i>星</i><span>星图 StarMap</span></div>
<h1>%s</h1><p>%s</p><a href="/login">返回登录页</a></div>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(detail))
	c.Data(code, "text/html; charset=utf-8", []byte(body))
}
