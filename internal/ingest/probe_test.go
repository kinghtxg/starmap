package ingest

// 探针上报入口（POST /api/ingest/probe）的行为测试。
//
// 这个接口是**外部数据进系统的第一个门**：探针（可能是别人部署的、可能是被改过的）
// 往这里灌报文。它的正确性有两层：
//  1. 解析层：字段名与探针对齐、时间戳兜底；
//  2. 保护层：通道满时要丢包而不是阻塞——HTTP 请求一旦被挂住，
//     探针那边会堆积、重试、雪崩，最后把采集端也拖垮。
//
// 第二层特别容易被"优化"掉：把 select/default 改成直接 `out <- p` 看起来更"不丢数据"，
// 实际是把背压一路传回探针。所以这里钉住它。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/parser"
)

func probePost(t *testing.T, h gin.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/ingest/probe", h)

	var buf bytes.Buffer
	switch v := body.(type) {
	case string:
		buf.WriteString(v)
	default:
		if err := json.NewEncoder(&buf).Encode(v); err != nil {
			t.Fatalf("编码请求体失败: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/probe", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeProbeResp(t *testing.T, w *httptest.ResponseRecorder) (accepted, total int) {
	t.Helper()
	var resp struct {
		Accepted int `json:"accepted"`
		Total    int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v（%s）", err, w.Body.String())
	}
	return resp.Accepted, resp.Total
}

// TestProbeHandlerAccepts 正常路径：报文全部进通道，计数如实回报。
func TestProbeHandlerAccepts(t *testing.T) {
	out := make(chan *parser.PacketInfo, 16)
	sentAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	report := ProbeReport{
		ProbeID: "probe-01",
		SentAt:  sentAt,
		Packets: []parser.PacketInfo{
			{Timestamp: sentAt, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Proto: "tcp", Length: 120},
			{Timestamp: sentAt, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SrcPort: 5678, DstPort: 443, Proto: "tcp", Length: 200},
		},
	}

	w := probePost(t, ProbeHandler(out), report)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	accepted, total := decodeProbeResp(t, w)
	if accepted != 2 || total != 2 {
		t.Fatalf("accepted=%d total=%d，期望 2/2", accepted, total)
	}
	if len(out) != 2 {
		t.Fatalf("通道里只有 %d 个报文，期望 2", len(out))
	}
	first := <-out
	if first.SrcIP != "10.0.0.1" || first.DstPort != 80 {
		t.Fatalf("报文内容错位: %+v", first)
	}
}

// TestProbeHandlerFillsTimestamp 探针没填时间戳时，用 SentAt 兜底。
//
// 不兜底的后果不是"少个字段"：零值时间戳会让这条会话落到 1970 年，
// 拓扑上表现为"这台机器很久以前有一次流量"，而实际它是刚刚发生的。
func TestProbeHandlerFillsTimestamp(t *testing.T) {
	out := make(chan *parser.PacketInfo, 4)
	sentAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	report := ProbeReport{
		ProbeID: "probe-02",
		SentAt:  sentAt,
		Packets: []parser.PacketInfo{
			{SrcIP: "10.0.0.9", DstIP: "10.0.0.8"}, // Timestamp 故意留空
		},
	}
	w := probePost(t, ProbeHandler(out), report)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	got := <-out
	if !got.Timestamp.Equal(sentAt) {
		t.Fatalf("时间戳没有兜底: %v，期望 %v", got.Timestamp, sentAt)
	}
}

// TestProbeHandlerDropsWhenFull 通道满时必须丢包并立刻返回，不能挂住请求。
func TestProbeHandlerDropsWhenFull(t *testing.T) {
	out := make(chan *parser.PacketInfo) // 无缓冲且没有消费者 → 必然满
	report := ProbeReport{
		ProbeID: "probe-03",
		SentAt:  time.Now(),
		Packets: []parser.PacketInfo{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
			{SrcIP: "10.0.0.3", DstIP: "10.0.0.4"},
			{SrcIP: "10.0.0.5", DstIP: "10.0.0.6"},
		},
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- probePost(t, ProbeHandler(out), report) }()

	select {
	case w := <-done:
		// 接口必须仍返回 200：探针侧不该因为服务端内部背压而看到错误并疯狂重试
		if w.Code != http.StatusOK {
			t.Fatalf("通道满时状态码 %d: %s", w.Code, w.Body.String())
		}
		accepted, total := decodeProbeResp(t, w)
		if total != 3 {
			t.Fatalf("total=%d，期望 3", total)
		}
		if accepted != 0 {
			t.Fatalf("无消费者的无缓冲通道里 accepted=%d，期望 0", accepted)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("通道满时请求被挂住了——背压传回了探针，会引发重试雪崩")
	}
}

// TestProbeHandlerRejectsBadInput 非法上报必须 400，不能进管道。
func TestProbeHandlerRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body any
		why  string
	}{
		{"非法 JSON", `{"probe_id":`, "截断的 JSON"},
		{"空对象", `{}`, "缺 probe_id 与 packets"},
		{"只有 probe_id", map[string]any{"probe_id": "p1"}, "缺 packets（nil）"},
		{"只有 packets", map[string]any{"packets": []any{map[string]any{"SrcIP": "1.1.1.1"}}}, "缺 probe_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := make(chan *parser.PacketInfo, 8)
			w := probePost(t, ProbeHandler(out), c.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s 应 400，实际 %d: %s", c.why, w.Code, w.Body.String())
			}
			if len(out) != 0 {
				t.Fatalf("被拒的上报却往通道里塞了 %d 个报文", len(out))
			}
		})
	}
}

// TestProbeHandlerEmptyBatchOK 空批次（packets: []）是合法的空上报，返回 200。
//
// 这条不是"顺手测一下"，而是钉住一个容易误判的语义：
// `binding:"required"` 对 slice 只拦 nil，**不拦空数组**（validator 判的是 IsNil）。
// 于是"没带 packets"和"带了一个空数组"走了两条不同的路——前者 400、后者 200。
//
// 后者必须放行：探针在"这一轮没有新报文"时发空批次是正常的，
// 若判成 400，探针侧会以为上报失败并开始重试，白白放大请求量。
func TestProbeHandlerEmptyBatchOK(t *testing.T) {
	out := make(chan *parser.PacketInfo, 8)
	w := probePost(t, ProbeHandler(out), map[string]any{
		"probe_id": "p-empty",
		"packets":  []any{},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("空批次应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	accepted, total := decodeProbeResp(t, w)
	if accepted != 0 || total != 0 {
		t.Fatalf("空批次 accepted=%d total=%d，期望 0/0", accepted, total)
	}
	if len(out) != 0 {
		t.Fatalf("空批次往通道里塞了 %d 个报文", len(out))
	}
}

// TestProbeReportJSONFieldNames 探针与服务端的字段名契约。
//
// PacketInfo 没有 json tag，所以线上传的是 Go 字段名（"SrcIP" 而不是 "src_ip"）。
// 这是一条隐式契约：给这些字段补一个 snake_case 的 tag，所有已部署的探针
// 就会立刻上报一堆零值字段——IP 全空、端口全 0，而接口照样返回 200。
//
// 所以这里显式钉住"线上到底长什么样"，将来要改就必须同时改探针并考虑兼容。
func TestProbeReportJSONFieldNames(t *testing.T) {
	raw := []byte(`{
	  "probe_id": "probe-x",
	  "sent_at": "2026-03-04T05:06:07Z",
	  "packets": [{
	    "Timestamp": "2026-03-04T05:06:07Z",
	    "SrcIP": "10.0.0.1", "DstIP": "10.0.0.2",
	    "SrcPort": 1234, "DstPort": 80, "Proto": "tcp",
	    "SNI": "oa.corp.local", "JA3": "abc", "UserAgent": "curl/8.0"
	  }]
	}`)

	out := make(chan *parser.PacketInfo, 4)
	w := probePost(t, ProbeHandler(out), string(raw))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	got := <-out
	if got.SrcIP != "10.0.0.1" || got.DstIP != "10.0.0.2" || got.SrcPort != 1234 || got.DstPort != 80 {
		t.Fatalf("五元组没解析出来，字段名契约可能被改了: %+v", got)
	}
	// 预解析的会话元数据必须一起进来：frp/clash/reverse_proxy 规则靠这些字段，
	// 丢了它们这三类检测会整体失效（1.4 踩过一次）。
	if got.SNI != "oa.corp.local" || got.JA3 != "abc" || got.UserAgent != "curl/8.0" {
		t.Fatalf("预解析元数据丢了（检测规则会失灵）: %+v", got)
	}
}
