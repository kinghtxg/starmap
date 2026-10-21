// Package logging 结构化日志。
//
// 为什么换掉 log.Printf：文本日志在排障时的致命问题是**不可按字段过滤**。
// 一个政务网现场，运维要回答的典型问题是"10.10.1.101 这台代理，过去一小时
// 有哪些请求 500 了"——文本日志只能 grep 再肉眼筛，结构化日志一行一个字段。
//
// 设计取舍：
//   - 用标准库 log/slog，不引第三方日志库（zerolog/zap）：本项目依赖已经够多，
//     slog 的性能对本场景（每秒几千条以内）完全够用。
//   - 开发用 Text（肉眼看），生产用 JSON（机器解析），一个开关切换。
//   - 每条日志带 request_id，跨中间件/handler/异步任务串起同一次请求。
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format 日志输出格式。
type Format string

const (
	// FormatText 人类可读，开发环境用。
	FormatText Format = "text"
	// FormatJSON 单行 JSON，生产环境用（采集器/ELK 直接吃）。
	FormatJSON Format = "json"
)

// Options 日志配置。
type Options struct {
	Level  string    // debug | info | warn | error（默认 info）
	Format Format    // text | json（默认 text）
	Output io.Writer // 默认 os.Stderr
	// AddSource 输出文件:行号，排障时有用但会增加约 15% 开销，默认关闭。
	AddSource bool
}

// ParseLevel 解析日志级别，非法值回落到 info。
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// levelVar 全局级别开关。
//
// 用 slog.LevelVar 而不是把级别写进 HandlerOptions.Level：后台改日志级别要**立即生效**，
// 而 HandlerOptions.Level 在 Handler 构造时就固化了，改它必须重建 Handler
// （重建会丢掉已 SetDefault 的引用，各处 slog.Default() 拿到的还是旧 Handler）。
// LevelVar 是并发安全的，可以在运行期直接改。
var levelVar = new(slog.LevelVar)

// Setup 初始化全局 logger。返回构造好的 logger 便于测试注入。
func Setup(o Options) *slog.Logger {
	out := o.Output
	if out == nil {
		out = os.Stderr
	}
	levelVar.Set(ParseLevel(o.Level))
	hopt := &slog.HandlerOptions{
		Level:     levelVar,
		AddSource: o.AddSource,
	}
	var h slog.Handler
	// slog 内置 Handler 并发安全（内部已加锁），无需再包一层同步写入。
	if o.Format == FormatJSON {
		h = slog.NewJSONHandler(out, hopt)
	} else {
		h = slog.NewTextHandler(out, hopt)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

// SetLevel 运行期调整日志级别（PUT /api/config 调用）。非法值回落到 info。
func SetLevel(s string) { levelVar.Set(ParseLevel(s)) }

// L 返回全局 logger（slog.Default 的便捷别名）。
func L() *slog.Logger { return slog.Default() }

// ---------- request id ----------

// ctxKey 私有上下文键类型，避免与其他包的 key 冲突。
type ctxKey int

const ctxKeyRequestID ctxKey = iota

// NewRequestID 生成 16 位十六进制请求 ID（8 字节随机）。
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败极罕见；退化为固定前缀，不能因此中断请求
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}

// WithRequestID 把请求 ID 放进 context。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestIDFrom 从 context 取请求 ID，没有则返回空串。
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// FromContext 返回带 request_id 字段的 logger，供 handler 内部使用。
func FromContext(ctx context.Context) *slog.Logger {
	l := slog.Default()
	if id := RequestIDFrom(ctx); id != "" {
		return l.With("request_id", id)
	}
	return l
}

// ---------- 便捷写法 ----------

// Err 把 error 包装成 slog 属性；err 为 nil 时返回空属性（不会输出 "err": null）。
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String("err", err.Error())
}

// Fmt 把任意值格式化为字符串属性（仅用于非结构化字段，如 IP 列表）。
func Fmt(key string, v any) slog.Attr {
	return slog.String(key, fmt.Sprint(v))
}
