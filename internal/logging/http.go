package logging

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// HeaderRequestID 请求 ID 的响应头名。
// 回写到响应头，方便用户报障时直接报这个 ID 让我们反查整条链路。
const HeaderRequestID = "X-Request-Id"

// slowRequestThreshold 超过该耗时的请求打 Warn（默认 2 秒，与拓扑同步周期一致）。
const slowRequestThreshold = 2 * time.Second

// Middleware 访问日志 + 请求 ID 注入。
//
// 输出字段固定（便于日志平台建索引）：
//
//	http.method / http.path / http.status / http.duration_ms /
//	http.bytes / http.route / client.ip / user.agent / auth.subject / request_id
//
// 级别策略：5xx → Error，4xx 与慢请求 → Warn，其余 Info。
// 健康检查与静态资源不记录（否则一个页面加载就淹没十几条日志）。
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 优先用上游反代传入的 ID（同一条请求跨系统串联），否则自己生成。
		rid := c.GetHeader(HeaderRequestID)
		if rid == "" {
			rid = NewRequestID()
		}
		c.Set("request_id", rid)
		c.Header(HeaderRequestID, rid)
		c.Request = c.Request.WithContext(WithRequestID(c.Request.Context(), rid))

		start := time.Now()
		c.Next()
		elapsed := time.Since(start)

		path := c.Request.URL.Path
		if skipAccessLog(path) {
			return
		}

		attrs := []any{
			"http.method", c.Request.Method,
			"http.path", path,
			"http.status", c.Writer.Status(),
			"http.duration_ms", float64(elapsed.Microseconds()) / 1000.0,
			"http.bytes", c.Writer.Size(),
			"client.ip", c.ClientIP(),
			"request_id", rid,
		}
		if route := c.FullPath(); route != "" {
			attrs = append(attrs, "http.route", route)
		}
		if ua := c.Request.UserAgent(); ua != "" {
			attrs = append(attrs, "user.agent", truncate(ua, 160))
		}
		if sub, ok := c.Get("auth.subject"); ok {
			if s, ok := sub.(string); ok && s != "" {
				attrs = append(attrs, "auth.subject", s)
			}
		}
		if len(c.Errors) > 0 {
			attrs = append(attrs, "http.error", c.Errors.String())
		}
		// 审计类操作（写操作）额外打一条，便于按动作检索
		l := slog.Default()

		switch {
		case c.Writer.Status() >= 500:
			l.Error("http_request", attrs...)
		case c.Writer.Status() >= 400:
			l.Warn("http_request", attrs...)
		case elapsed >= slowRequestThreshold:
			l.Warn("http_slow_request", attrs...)
		default:
			l.Info("http_request", attrs...)
		}
	}
}

// skipAccessLog 健康检查与静态资源不记访问日志。
func skipAccessLog(path string) bool {
	switch {
	case path == "/api/health" || path == "/healthz" || path == "/readyz" || path == "/metrics":
		return true
	case len(path) >= 7 && path[:7] == "/assets":
		return true
	case path == "/favicon.ico":
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
