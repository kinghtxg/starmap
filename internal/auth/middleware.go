package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 静态资源后缀：未认证也放行（登录页自身的 CSS/JS/图标）。
var staticExts = []string{
	".js", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg", ".svg",
	".woff", ".woff2", ".ttf", ".gif", ".json", ".txt",
}

// Middleware 返回认证中间件。
//
//	mode=none  → 直接放行（K1：与未启用完全一致，不新增任何重定向/阻断）
//	其它模式   → 校验 HMAC 签名的会话 Cookie；未认证时 HTML 页面 302 到 /login，
//	             /api/* 返回 401 JSON
//
// 始终放行的路径：/api/health、/login、/login.html、/api/auth/*、静态资源、
// 以及配置中的 PublicPaths。
func Middleware(cfg Config) gin.HandlerFunc {
	return shared(cfg).middleware()
}

func (r *runtime) middleware() gin.HandlerFunc {
	if !r.cfg.Enabled() {
		// K1 + K3：不启用时不产生任何行为差异（不重定向、不阻断）。
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		if r.isPublic(c.Request.URL.Path) {
			c.Next()
			return
		}
		claims, ok := r.sessionFromRequest(c)
		if !ok {
			r.deny(c)
			return
		}
		// 写入身份与角色。角色来自签名过的会话载荷，客户端无法伪造。
		c.Set(CtxSubject, claims.Sub)
		c.Set(CtxDisplayName, claims.Name)
		if claims.Role != "" {
			c.Set(CtxRole, claims.Role)
		}
		c.Next()
	}
}

// isPublic 判断路径是否无需认证即可访问。
func (r *runtime) isPublic(path string) bool {
	switch path {
	case "/login", "/login.html", "/api/health", "/favicon.ico", "/":
		return true
	}
	if strings.HasPrefix(path, "/api/auth/") || strings.HasPrefix(path, "/assets/") {
		return true
	}
	for _, p := range r.cfg.PublicPaths {
		p = strings.TrimSpace(p)
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// deny 未认证的处理：API 返回 401 JSON，页面 302 到登录页。
func (r *runtime) deny(c *gin.Context) {
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "未认证",
			"login": "/login",
			"mode":  r.cfg.Mode,
		})
		return
	}
	target := "/login"
	if path != "/" && strings.HasPrefix(path, "/") {
		target = "/login?" + returnToParam + "=" + urlEscape(path)
	}
	c.Redirect(http.StatusFound, target)
	c.Abort()
}

func urlEscape(s string) string {
	// 仅转义查询串中不允许的字符，保持路径可读。
	return strings.NewReplacer(
		" ", "%20",
		"\"", "%22",
		"<", "%3C",
		">", "%3E",
		"#", "%23",
		"&", "%26",
	).Replace(s)
}
