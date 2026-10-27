package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"乱七八糟":    slog.LevelInfo, // 非法值必须回落到 info，不能崩也不能静默关掉日志
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetupJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: "info", Format: FormatJSON, Output: &buf})
	L().Info("hello", "k", "v")

	var m map[string]any
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("JSON 格式日志无法解析: %v\n%s", err, line)
	}
	if m["msg"] != "hello" || m["k"] != "v" || m["level"] != "INFO" {
		t.Fatalf("字段不符: %#v", m)
	}
}

func TestSetupTextAndLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: "warn", Format: FormatText, Output: &buf})
	L().Info("should-be-dropped")
	L().Warn("should-keep")
	out := buf.String()
	if strings.Contains(out, "should-be-dropped") {
		t.Fatalf("warn 级别下仍输出了 info 日志: %s", out)
	}
	if !strings.Contains(out, "should-keep") {
		t.Fatalf("warn 日志丢失: %s", out)
	}
}

// TestSetLevelRuntime 后台改日志级别必须立即生效（LevelVar 的意义所在）。
func TestSetLevelRuntime(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: "error", Format: FormatText, Output: &buf})
	L().Info("hidden")
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("error 级别下不应输出 info")
	}
	SetLevel("debug")
	buf.Reset()
	L().Debug("visible-now")
	if !strings.Contains(buf.String(), "visible-now") {
		t.Fatal("SetLevel 未生效")
	}
	SetLevel("info") // 复位，避免影响其他用例
}

func TestRequestIDContext(t *testing.T) {
	if RequestIDFrom(context.Background()) != "" {
		t.Fatal("空 context 应返回空串")
	}
	//lint:ignore SA1012 刻意传 nil：RequestIDFrom 必须对 nil context 判空而不是 panic
	if RequestIDFrom(nil) != "" {
		t.Fatal("nil context 不应 panic")
	}
	ctx := WithRequestID(context.Background(), "abc123")
	if got := RequestIDFrom(ctx); got != "abc123" {
		t.Fatalf("request id 丢失: %q", got)
	}
}

// TestNewRequestIDUnique 断言请求 ID 的唯一性与格式。
// 原先只比较连续两次的结果（NewRequestID() == NewRequestID()），
// 既被 staticcheck 判为可疑表达式，也测不出"偶发碰撞"这种真实缺陷；
// 改为大样本去重，才是请求 ID 真正要保证的性质。
func TestNewRequestIDUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewRequestID()
		if id == "req-fallback" {
			t.Fatal("crypto/rand 读取失败，已退化为固定前缀")
		}
		if len(id) != 16 {
			t.Fatalf("请求 ID 应为 16 个十六进制字符，得到 %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("第 %d 次生成出现重复请求 ID: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestMiddlewareAccessLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	Setup(Options{Level: "info", Format: FormatText, Output: &buf})
	t.Cleanup(func() { Setup(Options{Level: "info", Format: FormatText}) })

	r := gin.New()
	r.Use(Middleware())
	r.GET("/api/demo/:id", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/api/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/api/boom", func(c *gin.Context) { c.String(http.StatusInternalServerError, "x") })
	r.GET("/api/denied", func(c *gin.Context) { c.String(http.StatusForbidden, "x") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/demo/42", nil)
	req.Header.Set("User-Agent", "unit-test")
	r.ServeHTTP(w, req)

	// request id 必须回写到响应头，用户报障时报这个就能反查
	if w.Header().Get(HeaderRequestID) == "" {
		t.Fatal("响应头缺少 X-Request-Id")
	}
	out := buf.String()
	for _, want := range []string{"http_request", "http.path=/api/demo/42", "http.status=200", "request_id="} {
		if !strings.Contains(out, want) {
			t.Fatalf("访问日志缺字段 %q:\n%s", want, out)
		}
	}

	// 健康检查不该刷日志
	buf.Reset()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if strings.Contains(buf.String(), "/api/health") {
		t.Fatal("健康检查不应产生访问日志")
	}

	// 5xx → ERROR，4xx → WARN
	buf.Reset()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/boom", nil))
	if !strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("5xx 应为 ERROR: %s", buf.String())
	}
	buf.Reset()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/denied", nil))
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("4xx 应为 WARN: %s", buf.String())
	}
}

// TestMiddlewareConcurrent 并发写入不能撕裂日志行（Handler 内部有锁，这里守住这个前提）。
func TestMiddlewareConcurrent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	Setup(Options{Level: "info", Format: FormatJSON, Output: &buf})

	r := gin.New()
	r.Use(Middleware())
	r.GET("/api/ping", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/ping", nil))
		}()
	}
	wg.Wait()

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("并发写出的日志行不可解析: %v\n%s", err, line)
		}
	}
}
