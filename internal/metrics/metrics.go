// Package metrics 运行指标导出（Prometheus 文本格式）。
//
// 为什么需要：1.0 只有 /api/stats 一个 JSON 快照，人看得懂，但**接不进监控**。
// 大厂现场的常态是"指标进 Prometheus + 告警规则 + Grafana 看板"，
// 没有 /metrics 就等于要求运维每天手动点一次页面——这不叫可观测，叫巡检。
//
// 设计要点：
//   - 独立 Registry，不用 prometheus.DefaultRegisterer：避免第三方库（如 gin 中间件）
//     往里塞一堆我们用不上的指标，也便于测试里反复创建而不会 panic 重复注册。
//   - 状态类指标一律用 GaugeFunc 现读现算，不用 Set 推送：
//     推送式需要每个变更点都记得更新，漏一处就是"看板数字不对"的经典事故。
//   - HTTP 指标用路由模板（c.FullPath()）作 label，**不用原始 URL**：
//     否则 /api/nodes/123、/api/nodes/124 会各生成一条时间序列，直接把 Prometheus 打爆。
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Providers 由调用方提供的实时状态读取函数（nil 表示该项不导出）。
type Providers struct {
	TopologyNodes   func() int
	TopologyEdges   func() int
	SessionsActive  func() int
	SessionsDropped func() int64
	SessionsEvicted func() int64
	EventsPending   func() int
	AssetsUnmanaged func() int
}

// Metrics 指标集合。
type Metrics struct {
	reg *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	httpInFlight prometheus.Gauge

	ingestPackets *prometheus.CounterVec
	ingestBytes   prometheus.Counter

	detectRuns  prometheus.Counter
	detectDur   prometheus.Histogram
	detectNew   prometheus.Counter
	probeReport *prometheus.CounterVec
}

// New 创建指标集合并注册到独立 Registry。
func New(p Providers) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}

	m.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "starmap_http_requests_total",
		Help: "HTTP 请求总数（按路由模板、方法、状态码）",
	}, []string{"route", "method", "status"})

	m.httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "starmap_http_request_duration_seconds",
		Help:    "HTTP 请求耗时分布",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"route", "method"})

	m.httpInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "starmap_http_in_flight_requests",
		Help: "当前正在处理的 HTTP 请求数",
	})

	m.ingestPackets = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "starmap_ingest_packets_total",
		Help: "摄入报文总数（按来源：capture/pcap/probe）",
	}, []string{"source"})

	m.ingestBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "starmap_ingest_bytes_total",
		Help: "摄入字节总数",
	})

	m.detectRuns = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "starmap_detection_runs_total",
		Help: "检测评估轮次",
	})
	m.detectDur = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "starmap_detection_duration_seconds",
		Help:    "单轮检测评估耗时",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})
	m.detectNew = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "starmap_detection_events_total",
		Help: "检测产出的新事件总数",
	})
	m.probeReport = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "starmap_probe_reports_total",
		Help: "探针上报次数（按结果 ok/unauthorized/bad_request）",
	}, []string{"result"})

	reg.MustRegister(
		m.httpRequests, m.httpDuration, m.httpInFlight,
		m.ingestPackets, m.ingestBytes,
		m.detectRuns, m.detectDur, m.detectNew, m.probeReport,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m.registerGaugeFuncs(reg, p)
	return m
}

// registerGaugeFuncs 把实时状态注册成 GaugeFunc（现读现算，不需要任何推送）。
func (m *Metrics) registerGaugeFuncs(reg *prometheus.Registry, p Providers) {
	add := func(name, help string, f func() int) {
		if f == nil {
			return
		}
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 {
			return float64(f())
		}))
	}
	add("starmap_topology_nodes", "拓扑中的节点数（含聚合节点）", p.TopologyNodes)
	add("starmap_topology_edges", "拓扑中的可见边数", p.TopologyEdges)
	add("starmap_sessions_active", "内存会话表当前条数", p.SessionsActive)
	add("starmap_events_pending", "待复核事件数", p.EventsPending)
	add("starmap_assets_unmanaged", "台账外（未被在册登记）设备数", p.AssetsUnmanaged)

	if p.SessionsDropped != nil {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "starmap_sessions_dropped_total",
			Help: "因会话表容量上限被丢弃的新会话数（>0 说明上限打满，需调参）",
		}, func() float64 { return float64(p.SessionsDropped()) }))
	}
	if p.SessionsEvicted != nil {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "starmap_sessions_evicted_total",
			Help: "被回收（关闭/静默/超龄）的会话数",
		}, func() float64 { return float64(p.SessionsEvicted()) }))
	}
}

// Handler 返回 /metrics 的 HTTP handler。
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Registry 暴露底层 Registry（测试用）。
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Middleware 记录 HTTP 请求指标。
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// /metrics 自身不计入，否则每次抓取都会污染指标
		if c.Request.URL.Path == "/metrics" {
			c.Next()
			return
		}
		m.httpInFlight.Inc()
		start := time.Now()
		c.Next()
		m.httpInFlight.Dec()

		route := c.FullPath()
		if route == "" {
			// 未匹配路由：用固定标签值，避免用原始 URL 造成标签爆炸
			route = "unmatched"
		}
		status := strconv.Itoa(c.Writer.Status())
		m.httpRequests.WithLabelValues(route, c.Request.Method, status).Inc()
		m.httpDuration.WithLabelValues(route, c.Request.Method).Observe(time.Since(start).Seconds())
	}
}

// ---------- 业务埋点（供各子系统调用） ----------

// IngestPacket 记录一个摄入报文。source: capture | pcap | probe
func (m *Metrics) IngestPacket(source string, bytes int64) {
	m.ingestPackets.WithLabelValues(source).Inc()
	if bytes > 0 {
		m.ingestBytes.Add(float64(bytes))
	}
}

// DetectionRun 记录一轮检测评估。
func (m *Metrics) DetectionRun(d time.Duration, newEvents int) {
	m.detectRuns.Inc()
	m.detectDur.Observe(d.Seconds())
	if newEvents > 0 {
		m.detectNew.Add(float64(newEvents))
	}
}

// ProbeReport 记录一次探针上报结果。
func (m *Metrics) ProbeReport(result string) {
	m.probeReport.WithLabelValues(result).Inc()
}
