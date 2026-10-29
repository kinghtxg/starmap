package ti

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(ep string, key string) *Client {
	return New(Config{Enabled: true, Endpoint: ep, APIKey: key, TimeoutMS: 2000, CacheSeconds: 60})
}

// 扁平格式：直接给出 score/verdict/tags。
func TestLookupFlatFormat(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if ip := r.URL.Query().Get("ip"); ip != "93.184.216.34" {
			t.Errorf("查询参数 ip = %q", ip)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"score": 87, "verdict": "malicious", "tags": []string{"c2", "scanner"}, "source": "内部情报平台",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "secret-key")
	res, err := c.Lookup(context.Background(), "93.184.216.34", true)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotAuth != "Bearer secret-key" {
		t.Fatalf("应携带 API Key，实际 %q", gotAuth)
	}
	if res.Score != 87 || res.Verdict != VerdictMalicious {
		t.Fatalf("结果错误: %+v", res)
	}
	if len(res.Tags) != 2 {
		t.Fatalf("标签错误: %+v", res.Tags)
	}
}

// VirusTotal v3 风格：没有 score，用 last_analysis_stats 折算。
func TestLookupVTStyle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":8,"suspicious":2,"harmless":50,"undetected":10},"tags":["c2"]}}}`))
	}))
	defer srv.Close()

	res, err := newTestClient(srv.URL, "").Lookup(context.Background(), "8.8.8.8", true)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// (8*100 + 2*50) / 70 = 12
	if res.Score != 12 {
		t.Fatalf("score = %d, want 12", res.Score)
	}
	if res.Verdict != VerdictClean {
		t.Fatalf("verdict = %q, want clean", res.Verdict)
	}
}

// 内网地址绝不外发：这是数据边界，不是性能优化。
func TestLookupRejectsPrivateIP(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "")
	for _, ip := range []string{"192.168.31.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "fe80::1"} {
		if _, err := c.Lookup(context.Background(), ip, true); err == nil {
			t.Fatalf("%s 应拒绝查询", ip)
		} else if err != ErrPrivateIP {
			t.Fatalf("%s 错误类型不对: %v", ip, err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("内网地址不应产生任何外发请求，实际 %d 次", n)
	}
}

func TestLookupDisabled(t *testing.T) {
	c := New(Config{})
	if _, err := c.Lookup(context.Background(), "8.8.8.8", true); err != ErrDisabled {
		t.Fatalf("未配置时应返回 ErrDisabled，实际 %v", err)
	}
}

func TestLookupCacheAndForce(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"score":10,"verdict":"clean"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "")
	if _, err := c.Lookup(context.Background(), "1.1.1.1", false); err != nil {
		t.Fatal(err)
	}
	res, err := c.Lookup(context.Background(), "1.1.1.1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached {
		t.Fatal("第二次应命中缓存")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("缓存未生效，请求了 %d 次", n)
	}
	if _, err := c.Lookup(context.Background(), "1.1.1.1", true); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("force 应强制刷新，实际 %d 次", n)
	}
}

// 并发查同一个 IP 只发一次请求（单飞）。
func TestLookupSingleFlight(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(80 * time.Millisecond)
		w.Write([]byte(`{"score":50,"verdict":"suspicious"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "")
	done := make(chan struct{})
	for i := 0; i < 5; i++ {
		go func() { c.Lookup(context.Background(), "8.8.4.4", false); done <- struct{}{} }()
	}
	for i := 0; i < 5; i++ {
		<-done
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("并发应合并为 1 次请求，实际 %d 次", n)
	}
}

func TestLookupErrorKinds(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, "API Key"},
		{http.StatusTooManyRequests, "频繁"},
		{http.StatusInternalServerError, "HTTP 500"},
	}
	for _, cs := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(cs.code)
		}))
		_, err := newTestClient(srv.URL, "").Lookup(context.Background(), "8.8.8.8", true)
		if err == nil || !strings.Contains(err.Error(), cs.want) {
			t.Fatalf("HTTP %d 的错误信息应包含 %q，实际 %v", cs.code, cs.want, err)
		}
		srv.Close()
	}
}

// 端点支持 {ip} 占位（很多平台是 /ip/{ip} 形式）。
func TestBuildURLPlaceholder(t *testing.T) {
	c := New(Config{Enabled: true, Endpoint: "https://intel.example.com/v1/ip/{ip}?fields=all"})
	got := c.buildURL("93.184.216.34")
	if got != "https://intel.example.com/v1/ip/93.184.216.34?fields=all" {
		t.Fatalf("占位替换错误: %s", got)
	}
}

func TestParseUnknownBody(t *testing.T) {
	res, err := parse(nil)
	if err != nil || res.Verdict != VerdictUnknown {
		t.Fatalf("空响应应视为无记录: %+v %v", res, err)
	}
	if _, err := parse([]byte("<html>gateway</html>")); err == nil {
		t.Fatal("非 JSON 应报错，而不是静默当成无记录")
	}
}
