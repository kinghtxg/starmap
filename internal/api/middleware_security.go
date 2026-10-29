package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 安全响应头与请求体上限。
//
// 这两件事都是"上线标准"的硬指标，但内网产品最容易漏：
//  1. 没有 X-Frame-Options / frame-ancestors，攻击者可以在自己的页面里用 iframe
//     套住 StarMap，诱导已登录的管理员点「删除资产」——点击劫持不需要任何漏洞。
//  2. 没有 X-Content-Type-Options，旧浏览器会按内容猜类型，把上传的文本当脚本执行。
//  3. 没有请求体上限，任何一个 POST 都能用超大 body 把内存吃光——
//     `PUT /api/config` 尤其危险，它把 body 全量读进内存再反序列化成 map。
//
// CSP 为什么带 'unsafe-inline'：产品刻意做成零构建、零 CDN（内网离线可用），
// 每个页面都内联 <script> 与 <style>。不加 'unsafe-inline' 页面直接白屏。
// 即便如此，CSP 仍能挡住三件真实的事：外部脚本注入、eval、以及 form 提交到外站。

const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'"

// securityHeaders 给所有响应加安全头。
// 顺序：放在访问日志之后、认证之前——未认证请求同样需要这些头（登录页也怕被套 iframe）。
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		// 防止 MIME 嗅探：上传的 .txt 不会被当成 .js 执行
		h.Set("X-Content-Type-Options", "nosniff")
		// 双保险：老浏览器看 XFO，新浏览器看 CSP frame-ancestors
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		// 内网地址可能带 token / 路径信息，别顺着 Referer 漏给外部站点
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	}
}

// bodyLimitDefault 普通 JSON 接口的请求体上限。
// 2MB 足够容纳最长的备注/说明/配置（实测配置全量 JSON 约 1.3KB），
// 又远小于"能把进程打爆"的量级。
const bodyLimitDefault = 2 << 20

// bodyLimitOverrides 大体积入口单独放宽（这些 handler 内部还有各自的二次校验）。
var bodyLimitOverrides = map[string]int64{
	"/api/ingest/pcap":   MaxPCAPUpload,  // PCAP 上传 200MB
	"/api/ingest/probe":  64 << 20,       // 探针批量上报
	"/api/ledger/import": ledgerMaxBytes, // 台账 CSV 16MB
	"/api/intel/push":    64 << 20,       // 情报推送（定期全量/增量，条数另有上限）
}

// bodyLimit 给请求体套上确定的读取上限。
//
// 为什么必须在中间件层做而不是各 handler 自己做：漏一处就是一个 OOM 入口，
// 而"新增接口时忘了加"几乎是必然事件。默认值兜底 + 白名单放宽，
// 让"忘记"变成安全的那一侧。
func bodyLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		n := int64(bodyLimitDefault)
		path := c.Request.URL.Path
		for prefix, limit := range bodyLimitOverrides {
			if strings.HasPrefix(path, prefix) {
				n = limit
				break
			}
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		}
		c.Next()
	}
}
