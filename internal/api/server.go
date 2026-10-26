// Package api Gin 路由 + 全部 REST API + 静态文件托管（SPEC §6 + §10.6）。
// 注意：前端契约使用 PascalCase 字段、字符串节点 ID（聚合节点 "subnet:<cidr>"），
// API 层负责 model（snake_case）与前端 DTO 的转换。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/auth"
	"starmap/internal/detect"
	"starmap/internal/discover"
	"starmap/internal/ingest"
	"starmap/internal/ledger"
	"starmap/internal/logging"
	"starmap/internal/metrics"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
	"starmap/internal/version"
	"starmap/web"
)

// MaxPCAPUpload PCAP 上传上限（SPEC §10.8：200MB）
const MaxPCAPUpload = 200 << 20

// Deps API 层依赖
type Deps struct {
	Store      *store.Store
	Engine     *topology.Engine
	Detector   *detect.Detector
	Reviewer   *review.Reviewer
	Scanner    *probe.Scanner
	Cfg        *model.SystemConfig
	Aggregator *parser.Aggregator
	// Discover 主动发现执行器（1.2）；nil 表示不提供主动发现接口。
	Discover *discover.Runner
	// PacketCh 探针上报报文通道（ProbeHandler 写入）
	PacketCh chan *parser.PacketInfo
	// PersistConfig PUT /api/config 持久化钩子
	PersistConfig func(model.SystemConfig) error
	// Metrics 指标集合（nil 表示不暴露 /metrics）
	Metrics *metrics.Metrics
	// Middleware 附加中间件：在认证之后、业务路由之前执行。
	// 用途：外部插件注入（如自定义审计/租户识别），以及测试里模拟"已认证且角色为 X"。
	Middleware []gin.HandlerFunc
	Version    string
}

// Server HTTP 服务
type Server struct {
	d Deps

	mu             sync.Mutex
	capCancel      context.CancelFunc
	capRunning     bool
	capIfaces      []string
	capPackets     int64 // 抓包来源累计报文
	packetsTotal   int64 // 全部来源累计报文
	ingestInFlight int32

	// 端口扫描任务（V1.2）
	scanMu    sync.Mutex
	scanTasks map[string]*scanTask
	scanSeq   int64

	// 主动发现任务（1.2）
	discMu    sync.Mutex
	discTasks map[string]*discoverTask
	discSeq   int64
}

// scanTask 主动端口扫描任务状态。
type scanTask struct {
	ID      string    `json:"id"`
	Target  string    `json:"target"`
	Status  string    `json:"status"` // running | done | error
	Found   int       `json:"found"`
	Error   string    `json:"error,omitempty"`
	Started time.Time `json:"started"`
	Done    time.Time `json:"done,omitempty"`
}

// NewRouter 构建 Gin 引擎与全部路由。
func NewRouter(d Deps) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	s := &Server{d: d, scanTasks: map[string]*scanTask{}, discTasks: map[string]*discoverTask{}}
	if s.d.Version == "" {
		s.d.Version = version.String()
	}
	// 访问日志 + request_id 必须最外层：Recovery 在它内层，panic 被兜住后
	// 这里仍能拿到 500 状态并打出完整日志（若顺序反过来，panic 会跳过本层收尾逻辑）。
	r.Use(logging.Middleware())
	r.Use(gin.Recovery())
	if s.d.Metrics != nil {
		r.Use(s.d.Metrics.Middleware())
	}
	r.Use(s.corsMiddleware())
	// 可选账号系统 / APSSO SSO 门卫（默认 mode=none，不启用时零行为差异，见 docs/AUTH-APSSO.md）
	r.Use(auth.Middleware(d.Cfg.Auth))
	// 附加中间件必须在路由注册之前挂载：RequireRole 是绑在路由上的，
	// 晚于它挂载中间件就来不及把角色写进上下文。
	for _, mw := range d.Middleware {
		if mw != nil {
			r.Use(mw)
		}
	}
	auth.RegisterRoutes(r, d.Cfg.Auth)

	api := r.Group("/api")
	// 权限分层：写死在路由表上，看一眼就知道谁能调什么。
	// 未启用认证（mode=none）时 auth.Role 恒为 admin，所有分组等价放行（K1 零配置可用）。
	ro := api.Group("", auth.RequireRole(auth.RoleViewer))
	rw := api.Group("", auth.RequireRole(auth.RoleOperator))
	adm := api.Group("", auth.RequireRole(auth.RoleAdmin))
	{
		// ---- 只读：巡检/审计账号即可访问 ----
		api.GET("/health", s.health)
		ro.GET("/topology", s.topologySnapshot)
		ro.GET("/topology/subnet/*cidr", s.subnetSnapshot)
		ro.GET("/subnets", s.listSubnets)
		ro.GET("/nodes/:id", s.nodeDetail)
		ro.GET("/events", s.listEvents)
		ro.GET("/whitelist", s.listWhitelist)
		ro.GET("/domains", s.listDomains)
		ro.GET("/config", s.getConfig)
		ro.GET("/audit", s.listAudit)
		ro.GET("/stats", s.stats)
		ro.GET("/capture/status", s.captureStatus)
		ro.GET("/assets", s.listAssets)
		ro.GET("/assets/stats", s.assetStats)
		ro.GET("/ports", s.listPorts)
		ro.GET("/ports/scan/:id", s.scanPortsStatus)
		ro.GET("/discover/plan", s.discoverPlan)
		ro.GET("/discover/status/:id", s.discoverStatus)
		ro.GET("/ledger", s.listLedger)
		ro.GET("/ledger/diff", s.ledgerDiff)
		ro.GET("/proxies", s.listProxies)
		ro.GET("/probes", s.listProbes)
		// 注意：/api/auth/me 由 internal/auth 独占注册（未启用认证时也返回 admin），
		// 这里绝不能再注册一次——Gin 对同一 method+path 重复注册会直接 panic。

		// ---- 操作：日常运维动作 ----
		rw.POST("/events/:id/review", s.reviewEvent)
		rw.POST("/whitelist", s.createWhitelist)
		rw.PUT("/whitelist/:id", s.updateWhitelist)
		rw.POST("/domains", s.createDomain)
		rw.PUT("/domains/:id", s.updateDomain)
		rw.POST("/ingest/pcap", s.ingestPCAP)
		rw.POST("/ingest/probe", s.ingestProbe)
		rw.POST("/probe/trigger", s.triggerProbe)
		rw.POST("/capture/start", s.captureStart)
		rw.POST("/capture/stop", s.captureStop)
		rw.POST("/assets/archive", s.archiveAsset)
		rw.PUT("/assets/:key", s.updateAsset)
		rw.POST("/ports/scan", s.scanPorts)
		rw.POST("/discover/run", s.discoverRun)
		rw.POST("/ledger/import", s.ledgerImport)

		// ---- 管理：改配置、删数据 ----
		adm.PUT("/config", s.putConfig)
		adm.DELETE("/whitelist/:id", s.deleteWhitelist)
		adm.DELETE("/domains/:id", s.deleteDomain)
		adm.DELETE("/assets/:key", s.deleteAsset)
		adm.DELETE("/ledger", s.clearLedger)
		adm.DELETE("/probes/:id", s.deleteProbe)
	}

	// 指标导出：Prometheus 抓取口。鉴权策略见 metricsGuard。
	if s.d.Metrics != nil {
		r.GET("/metrics", s.metricsGuard(), gin.WrapH(s.d.Metrics.Handler()))
	} else {
		// 未启用时必须显式 404，不能落到 SPA 兜底返回 HTML——
		// Prometheus 拿到 200 text/html 会报"解析失败"，排查方向全错；
		// 404 才是"这个部署没开指标"的准确表达。
		r.GET("/metrics", func(c *gin.Context) {
			fail(c, http.StatusNotFound, "指标导出未启用（metrics_enabled=false）")
		})
	}

	// 静态资源（embed.FS 单二进制分发）
	r.NoRoute(s.staticHandler)
	return r
}

// ---------- middleware ----------

func (s *Server) corsMiddleware() gin.HandlerFunc {
	// P0-4/P1-7：CORS 收紧为白名单。默认空 = 仅同源，不发 Access-Control-Allow-Origin，
	// 杜绝任意恶意网页跨域读写内网 StarMap。
	origins := s.d.Cfg.CorsOrigins
	return func(c *gin.Context) {
		if origin := c.Request.Header.Get("Origin"); origin != "" {
			if allowedOrigin(origin, origins) {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Probe-Token")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// allowedOrigin 判断 Origin 是否命中白名单；白名单为空则仅同源（含同 host 的 Origin）。
func allowedOrigin(origin string, allow []string) bool {
	if len(allow) == 0 {
		return false
	}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// authPlaceholder 已删除：认证由 internal/auth.Middleware 承担（默认 mode=none）。

// actor P0-4：审计日志 Actor 由硬编码 "api" 改为可追溯来源。
// 已启用账号系统时取登录身份，否则取客户端 IP。
func (s *Server) actor(c *gin.Context) string {
	if sub := auth.Subject(c); sub != "" {
		return sub
	}
	return c.ClientIP()
}

// secureEqual 常量时间字符串比较，用于 token 校验（避免逐字节比较泄漏前缀长度）。
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// probeTokenMiddleware 已废弃：探针 token 支持 header / query / body 三种来源，
// 由 ingestProbe 内部统一校验（middleware 读不到 JSON body）。
// token 校验失败时用 secureEqual 常量时间比较。
func fail(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"error": msg})
}

// ---------- 指标导出 ----------

// metricsGuard /metrics 的鉴权。
//
// 三种放行方式，按优先级：
//  1. 配置了 metrics_token → 必须带 X-Metrics-Token（常量时间比较）——
//     Prometheus 侧在 scrape_config 里加一个 header 即可，不依赖 Cookie；
//  2. 已认证且具备 admin 角色 → 放行（人工排查时直接浏览器打开）；
//  3. 未启用认证且来自回环地址 → 放行（本机 curl 调试）。
//
// 之所以不默认全开：/metrics 会暴露节点数、会话数、事件数等内网规模信息，
// 在政务网这类环境里本身就是敏感数据。
func (s *Server) metricsGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ""
		if s.d.Cfg != nil {
			token = strings.TrimSpace(s.d.Cfg.MetricsToken)
		}
		if token != "" {
			if secureEqual(c.GetHeader("X-Metrics-Token"), token) {
				c.Next()
				return
			}
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if auth.HasRole(c, auth.RoleAdmin) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// 身份查询见 internal/auth 的 /api/auth/me（未启用认证时返回 admin）。
// 这里不再单独实现 whoami：同一个事实只有一个来源，避免两处返回不一致。

// ---------- 健康/统计 ----------

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"version": s.d.Version,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) stats(c *gin.Context) {
	snap := s.d.Engine.Snapshot()
	events, _ := s.d.Store.ListEvents("", "")
	pending := 0
	for _, e := range events {
		if e.Status == model.EventStatusPending {
			pending++
		}
	}
	s.mu.Lock()
	capSt := gin.H{
		"Running":    s.capRunning,
		"Interfaces": s.capIfaces,
		"Packets":    s.capPackets,
		"Available":  ingest.CaptureAvailable(),
	}
	s.mu.Unlock()
	var aggSt parser.AggregatorStats
	if s.d.Aggregator != nil {
		aggSt = s.d.Aggregator.Stats()
	}
	c.JSON(http.StatusOK, gin.H{
		"NodeCount":     snap.Stats.NodeCount,
		"EdgeCount":     snap.Stats.EdgeCount,
		"ActiveNodes":   snap.Stats.ActiveNodes,
		"ActiveEdges":   snap.Stats.ActiveEdges,
		"TotalBytes":    snap.Stats.TotalBytes,
		"EventCount":    len(events),
		"PendingEvents": pending,
		"SessionCount":  aggSt.Active,
		"PacketCount":   atomic.LoadInt64(&s.packetsTotal),
		"Capture":       capSt,
		"GeneratedAt":   time.Now().UTC(),
		// 会话表容量治理指标（V1.0）：Dropped>0 说明上限打满、有数据被丢弃，
		// 此时应调大 session_max_count 或缩短 session_idle_seconds。
		"SessionTable": gin.H{
			"Active":      aggSt.Active,
			"MaxSessions": aggSt.MaxSessions,
			"Dropped":     aggSt.Dropped,
			"Evicted":     aggSt.Evicted,
		},
	})
}

// ---------- 拓扑 ----------

// nodeJSON 前端契约节点（PascalCase，字符串 ID）
type nodeJSON struct {
	ID         string   `json:"ID"`
	NumID      int64    `json:"NumID,omitempty"`
	IPs        []string `json:"IPs"`
	MAC        string   `json:"MAC"`
	FirstSeen  string   `json:"FirstSeen"`
	LastSeen   string   `json:"LastSeen"`
	Domain     string   `json:"Domain"`
	Labels     []string `json:"Labels"`
	RiskLevel  string   `json:"RiskLevel"`
	Active     bool     `json:"Active"`
	Aggregated bool     `json:"Aggregated,omitempty"`
	Location   string   `json:"Location,omitempty"` // 归属位置（探针位置归纳，V1.3）
	Anchor     bool     `json:"Anchor,omitempty"`   // 风险锚点：未参与网段聚合（V1.6）
	Members    int      `json:"Members,omitempty"`  // 聚合节点包含主机数（V1.6）
}

func toNodeJSON(n *model.Node) nodeJSON {
	id := topology.APINodeID(n)
	labels := n.Labels
	if labels == nil {
		labels = []string{}
	}
	ips := n.IPs
	if ips == nil {
		ips = []string{}
	}
	return nodeJSON{
		ID:         id,
		NumID:      n.ID,
		IPs:        ips,
		MAC:        n.MAC,
		FirstSeen:  n.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:   n.LastSeen.UTC().Format(time.RFC3339),
		Domain:     n.Domain,
		Labels:     labels,
		RiskLevel:  n.RiskLevel,
		Active:     n.Active,
		Aggregated: strings.Contains(id, "/"),
		Location:   n.Location,
		Anchor:     n.Anchor,
		Members:    n.Members,
	}
}

type edgeJSON struct {
	ID        string `json:"ID"`
	SrcID     string `json:"SrcID"`
	DstID     string `json:"DstID"`
	Protocol  string `json:"Protocol"`
	Bytes     int64  `json:"Bytes"`
	Packets   int64  `json:"Packets"`
	FirstSeen string `json:"FirstSeen"`
	LastSeen  string `json:"LastSeen"`
	Active    bool   `json:"Active"`
	Kind      string `json:"Kind,omitempty"` // traffic|owner，owner=按 IP 网段推导的归属关联（V1.6）
}

func toEdgeJSON(e topology.VisibleEdge) edgeJSON {
	return edgeJSON{
		ID:        e.Src + "->" + e.Dst + "|" + e.Protocol,
		SrcID:     e.Src,
		DstID:     e.Dst,
		Protocol:  e.Protocol,
		Bytes:     e.Bytes,
		Packets:   e.Packets,
		FirstSeen: e.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:  e.LastSeen.UTC().Format(time.RFC3339),
		Active:    e.Active,
		Kind:      e.Kind,
	}
}

func (s *Server) topologySnapshot(c *gin.Context) {
	snap := s.d.Engine.Snapshot()
	nodes := make([]nodeJSON, 0, len(snap.Nodes))
	for i := range snap.Nodes {
		nodes = append(nodes, toNodeJSON(&snap.Nodes[i]))
	}
	vedges := s.d.Engine.SnapshotEdgePairs()
	edges := make([]edgeJSON, 0, len(vedges))
	for _, e := range vedges {
		edges = append(edges, toEdgeJSON(e))
	}
	c.JSON(http.StatusOK, gin.H{
		"Nodes": nodes,
		"Edges": edges,
		"Stats": gin.H{
			"NodeCount":   snap.Stats.NodeCount,
			"EdgeCount":   snap.Stats.EdgeCount,
			"ActiveNodes": snap.Stats.ActiveNodes,
			"ActiveEdges": snap.Stats.ActiveEdges,
			"TotalBytes":  snap.Stats.TotalBytes,
		},
		"GeneratedAt": snap.GeneratedAt.UTC().Format(time.RFC3339),
	})
}

// listSubnets 网段清单（V1.4）：返回全部已发现的内网 /24 网段及统计。
// 回答"网内结构"：有哪些网段、每网段多少台、在线几台、网关是谁、最高风险。
func (s *Server) listSubnets(c *gin.Context) {
	if s.d.Engine == nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	subs := s.d.Engine.Subnets()
	if subs == nil {
		subs = []topology.SubnetInfo{}
	}
	c.JSON(http.StatusOK, subs)
}

func (s *Server) subnetSnapshot(c *gin.Context) {
	cidr := strings.TrimPrefix(c.Param("cidr"), "/")
	if cidr == "" {
		fail(c, http.StatusBadRequest, "缺少 cidr 参数")
		return
	}
	snap := s.d.Engine.SubnetSnapshot(cidr)
	if len(snap.Nodes) == 0 {
		fail(c, http.StatusNotFound, "网段不存在或未聚合: "+cidr)
		return
	}
	nodes := make([]nodeJSON, 0, len(snap.Nodes))
	have := make(map[string]bool, len(snap.Nodes))
	for i := range snap.Nodes {
		nj := toNodeJSON(&snap.Nodes[i])
		have[nj.ID] = true
		nodes = append(nodes, nj)
	}
	vedges := s.d.Engine.SubnetVisibleEdges(cidr)
	edges := make([]edgeJSON, 0, len(vedges))
	ends := make([]string, 0, len(vedges)*2)
	for _, e := range vedges {
		edges = append(edges, toEdgeJSON(e))
		ends = append(ends, e.Src, e.Dst)
	}
	// V1.6：把边的外部端点（其它聚合网段 / 外部 /24）补成上下文节点，
	// 否则下钻视图里指向外部的边因端点不存在被前端丢弃，跨网归属与出口方向都看不见。
	nodeCount := snap.Stats.NodeCount
	for _, ctx := range s.d.Engine.SubnetContextNodes(cidr, ends) {
		nj := toNodeJSON(&ctx)
		if have[nj.ID] {
			continue
		}
		have[nj.ID] = true
		nodes = append(nodes, nj)
		nodeCount++
	}
	c.JSON(http.StatusOK, gin.H{
		"Nodes": nodes,
		"Edges": edges,
		"Stats": gin.H{
			"NodeCount":   nodeCount,
			"EdgeCount":   snap.Stats.EdgeCount,
			"ActiveNodes": snap.Stats.ActiveNodes,
			"ActiveEdges": snap.Stats.ActiveEdges,
			"TotalBytes":  snap.Stats.TotalBytes,
		},
		"CIDR":        cidr,
		"GeneratedAt": snap.GeneratedAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) nodeDetail(c *gin.Context) {
	id := c.Param("id")
	kind, num, cidr := topology.ParseAPINodeID(id)
	switch kind {
	case "node":
		n := s.d.Engine.GetNode(num)
		if n == nil {
			fail(c, http.StatusNotFound, "节点不存在: "+id)
			return
		}
		c.JSON(http.StatusOK, gin.H{"Node": toNodeJSON(n), "Peers": s.peersOf(topology.APINodeID(n))})
	case "subnet":
		snap := s.d.Engine.SubnetSnapshot(cidr)
		if len(snap.Nodes) == 0 {
			fail(c, http.StatusNotFound, "网段不存在或未聚合: "+cidr)
			return
		}
		members := make([]nodeJSON, 0, len(snap.Nodes))
		for i := range snap.Nodes {
			members = append(members, toNodeJSON(&snap.Nodes[i]))
		}
		vedges := s.d.Engine.SubnetVisibleEdges(cidr)
		edges := make([]edgeJSON, 0, len(vedges))
		for _, e := range vedges {
			edges = append(edges, toEdgeJSON(e))
		}
		agg := model.Node{IPs: []string{cidr}, Labels: []string{topology.LabelSubnetAgg}}
		c.JSON(http.StatusOK, gin.H{
			"Node":    toNodeJSON(&agg),
			"Members": members,
			"Edges":   edges,
		})
	case "ext":
		n := s.d.Engine.NodeByExternalCIDR(cidr)
		if n == nil {
			fail(c, http.StatusNotFound, "外部聚合节点不存在: "+cidr)
			return
		}
		c.JSON(http.StatusOK, gin.H{"Node": toNodeJSON(n), "Peers": s.peersOf(topology.ExternalNodeID(cidr))})
	default:
		fail(c, http.StatusBadRequest, "非法节点 ID: "+id)
	}
}

func (s *Server) peersOf(apiID string) []gin.H {
	var peers []gin.H
	for _, e := range s.d.Engine.SnapshotEdgePairs() {
		var other string
		if e.Src == apiID {
			other = e.Dst
		} else if e.Dst == apiID {
			other = e.Src
		} else {
			continue
		}
		peers = append(peers, gin.H{"ID": other, "Protocol": e.Protocol, "Bytes": e.Bytes, "Packets": e.Packets})
	}
	return peers
}

// ---------- 事件 ----------

// eventJSON 前端契约事件
type eventJSON struct {
	ID         int64             `json:"ID"`
	Type       string            `json:"Type"`
	NodeID     int64             `json:"NodeID"`
	NodeAPID   string            `json:"NodeAPID,omitempty"`
	Title      string            `json:"Title"`
	Detail     string            `json:"Detail"`
	Evidence   map[string]string `json:"Evidence"`
	Status     string            `json:"Status"`
	Level      string            `json:"Level"`
	CreatedAt  string            `json:"CreatedAt"`
	UpdatedAt  string            `json:"UpdatedAt"`
	ReviewNote string            `json:"ReviewNote,omitempty"`
	Reviewer   string            `json:"Reviewer,omitempty"`
}

func (s *Server) toEventJSON(e *model.RiskEvent) eventJSON {
	ev := eventJSON{
		ID:         e.ID,
		Type:       e.Type,
		NodeID:     e.NodeID,
		Title:      e.Title,
		Detail:     e.Detail,
		Evidence:   e.Evidence,
		Status:     e.Status,
		Level:      e.Level,
		CreatedAt:  e.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:  e.UpdatedAt.UTC().Format(time.RFC3339),
		ReviewNote: e.ReviewNote,
		Reviewer:   e.Reviewer,
	}
	if ev.Evidence == nil {
		ev.Evidence = map[string]string{}
	}
	if n := s.d.Engine.GetNode(e.NodeID); n != nil {
		ev.NodeAPID = topology.APINodeID(n)
	}
	return ev
}

func (s *Server) listEvents(c *gin.Context) {
	evs, err := s.d.Store.ListEvents(c.Query("status"), c.Query("type"))
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]eventJSON, 0, len(evs))
	for i := range evs {
		out = append(out, s.toEventJSON(&evs[i]))
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) reviewEvent(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "非法事件 ID")
		return
	}
	var body struct {
		Action   string `json:"action"`
		Note     string `json:"note"`
		Reviewer string `json:"reviewer"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	ev, err := s.d.Reviewer.Review(id, body.Action, body.Note, body.Reviewer)
	switch {
	case errors.Is(err, review.ErrInvalidAction):
		fail(c, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, review.ErrEventNotFound):
		fail(c, http.StatusNotFound, err.Error())
		return
	case err != nil:
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, s.toEventJSON(ev))
}

// ---------- 白名单 ----------

type whitelistJSON struct {
	ID        int64  `json:"ID"`
	Kind      string `json:"Kind"`
	Value     string `json:"Value"`
	Note      string `json:"Note"`
	CreatedAt string `json:"CreatedAt"`
}

func toWhitelistJSON(w *model.WhitelistEntry) whitelistJSON {
	return whitelistJSON{ID: w.ID, Kind: w.Kind, Value: w.Value, Note: w.Note, CreatedAt: w.CreatedAt.UTC().Format(time.RFC3339)}
}

func (s *Server) listWhitelist(c *gin.Context) {
	list, err := s.d.Store.ListWhitelist()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]whitelistJSON, 0, len(list))
	for i := range list {
		out = append(out, toWhitelistJSON(&list[i]))
	}
	c.JSON(http.StatusOK, out)
}

func validWhitelistKind(k string) bool {
	switch strings.ToLower(k) {
	case "cidr", "ip", "host", "node":
		return true
	}
	return false
}

func (s *Server) createWhitelist(c *gin.Context) {
	var body whitelistJSON
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if !validWhitelistKind(body.Kind) {
		fail(c, http.StatusBadRequest, "非法 kind：仅支持 cidr|ip|host|node")
		return
	}
	if strings.TrimSpace(body.Value) == "" {
		fail(c, http.StatusBadRequest, "value 不能为空")
		return
	}
	w := &model.WhitelistEntry{Kind: strings.ToLower(body.Kind), Value: strings.TrimSpace(body.Value), Note: body.Note}
	id, err := s.d.Store.CreateWhitelistEntry(w)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	w.ID = id
	s.d.Reviewer.Audit(s.actor(c), "whitelist_create", w.Kind+":"+w.Value, body.Note)
	// 已有 pending 事件命中 → 自动 false_positive（§5）
	suppressed, _ := s.d.Reviewer.SuppressByWhitelist(*w, "api")
	c.JSON(http.StatusCreated, gin.H{"Entry": toWhitelistJSON(w), "Suppressed": suppressed})
}

func (s *Server) updateWhitelist(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "非法 ID")
		return
	}
	var body whitelistJSON
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if !validWhitelistKind(body.Kind) || strings.TrimSpace(body.Value) == "" {
		fail(c, http.StatusBadRequest, "非法 kind 或空 value")
		return
	}
	w := &model.WhitelistEntry{ID: id, Kind: strings.ToLower(body.Kind), Value: strings.TrimSpace(body.Value), Note: body.Note}
	if err := s.d.Store.UpdateWhitelistEntry(w); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "whitelist_update", w.Kind+":"+w.Value, body.Note)
	suppressed, _ := s.d.Reviewer.SuppressByWhitelist(*w, "api")
	c.JSON(http.StatusOK, gin.H{"Entry": toWhitelistJSON(w), "Suppressed": suppressed})
}

func (s *Server) deleteWhitelist(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "非法 ID")
		return
	}
	if err := s.d.Store.DeleteWhitelistEntry(id); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "whitelist_delete", strconv.FormatInt(id, 10), "")
	c.Status(http.StatusNoContent)
}

// ---------- 网络域 ----------

type domainJSON struct {
	ID    int64    `json:"ID"`
	Name  string   `json:"Name"`
	CIDRs []string `json:"CIDRs"`
	Color string   `json:"Color"`
}

func toDomainJSON(d *model.NetDomain) domainJSON {
	cidrs := d.CIDRs
	if cidrs == nil {
		cidrs = []string{}
	}
	return domainJSON{ID: d.ID, Name: d.Name, CIDRs: cidrs, Color: d.Color}
}

func (s *Server) refreshDomains() {
	ds, err := s.d.Store.ListDomains()
	if err == nil {
		s.d.Engine.SetDomains(ds)
	}
}

func (s *Server) listDomains(c *gin.Context) {
	ds, err := s.d.Store.ListDomains()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]domainJSON, 0, len(ds))
	for i := range ds {
		out = append(out, toDomainJSON(&ds[i]))
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) createDomain(c *gin.Context) {
	var body domainJSON
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		fail(c, http.StatusBadRequest, "name 不能为空")
		return
	}
	d := &model.NetDomain{Name: body.Name, CIDRs: body.CIDRs, Color: body.Color}
	id, err := s.d.Store.CreateDomain(d)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	d.ID = id
	s.refreshDomains()
	s.d.Reviewer.Audit(s.actor(c), "domain_create", d.Name, strings.Join(d.CIDRs, ","))
	c.JSON(http.StatusCreated, toDomainJSON(d))
}

func (s *Server) updateDomain(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "非法 ID")
		return
	}
	var body domainJSON
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	d := &model.NetDomain{ID: id, Name: body.Name, CIDRs: body.CIDRs, Color: body.Color}
	if err := s.d.Store.UpdateDomain(d); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.refreshDomains() // 修改 CIDR 后节点 Domain 归属随之更新
	s.d.Reviewer.Audit(s.actor(c), "domain_update", d.Name, strings.Join(d.CIDRs, ","))
	c.JSON(http.StatusOK, toDomainJSON(d))
}

func (s *Server) deleteDomain(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "非法 ID")
		return
	}
	if err := s.d.Store.DeleteDomain(id); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.refreshDomains()
	s.d.Reviewer.Audit(s.actor(c), "domain_delete", strconv.FormatInt(id, 10), "")
	c.Status(http.StatusNoContent)
}

// ingestProbe 远端探针上报（§10.6 schema：{probe_id, token?, packets:[...], flows:[Session 子集], ts}）。
// token 校验（§10.7）：配置 probe_token 时接受 header X-Probe-Token / query token / body token。
// flows 会转换为合成报文汇入统一 Aggregator → Engine 流水线（与抓包/PCAP 一致）。
func (s *Server) ingestProbe(c *gin.Context) {
	// 显式限长：探针上报是未经认证的入口（未配 probe_token 时），
	// 必须给出确定的读取上限，避免超大 body 把内存打满。
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<20)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(c, http.StatusRequestEntityTooLarge, "上报体积超过 64MB 上限")
			return
		}
		fail(c, http.StatusBadRequest, "读取请求体失败")
		return
	}
	var report struct {
		ProbeID  string              `json:"probe_id"`
		Name     string              `json:"name"`
		Location string              `json:"location"`
		Token    string              `json:"token"`
		SentAt   time.Time           `json:"sent_at"`
		Ts       time.Time           `json:"ts"`
		Packets  []parser.PacketInfo `json:"packets"`
		Flows    []probeFlow         `json:"flows"`
		Metadata map[string]string   `json:"metadata"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		fail(c, http.StatusBadRequest, "上报格式错误: "+err.Error())
		return
	}
	// 位置优先取 report.location，其次 metadata.location（兼容旧探针）
	location := report.Location
	if location == "" && report.Metadata != nil {
		location = report.Metadata["location"]
	}
	// token 校验
	if want := s.d.Cfg.ProbeToken; want != "" {
		got := c.GetHeader("X-Probe-Token")
		if got == "" {
			got = c.Query("token")
		}
		if got == "" {
			got = report.Token
		}
		if !secureEqual(got, want) {
			fail(c, http.StatusUnauthorized, "探针 token 校验失败")
			return
		}
	}
	if report.ProbeID == "" {
		fail(c, http.StatusBadRequest, "缺少 probe_id")
		return
	}
	if len(report.Packets) == 0 && len(report.Flows) == 0 {
		fail(c, http.StatusBadRequest, "packets 与 flows 均为空")
		return
	}
	baseTs := report.SentAt
	if baseTs.IsZero() {
		baseTs = report.Ts
	}
	if baseTs.IsZero() {
		baseTs = time.Now()
	}

	accepted := 0
	// 1) 原始报文直接进聚合器
	for i := range report.Packets {
		p := &report.Packets[i]
		if p.Timestamp.IsZero() {
			p.Timestamp = baseTs
		}
		if p.SrcIP == "" {
			continue
		}
		if p.Location == "" {
			p.Location = location
		}
		if s.d.Aggregator != nil {
			s.d.Aggregator.Ingest(p)
			accepted++
		}
	}
	// 2) flows → 合成上下行报文进聚合器（统一流水线）
	for _, f := range report.Flows {
		if f.Location == "" {
			f.Location = location
		}
		up, down := f.toPackets(baseTs)
		if up == nil {
			continue
		}
		if s.d.Aggregator != nil {
			s.d.Aggregator.Ingest(up)
			if down != nil {
				s.d.Aggregator.Ingest(down)
			}
			accepted++
		}
	}
	atomic.AddInt64(&s.packetsTotal, int64(accepted))

	// 探针注册（V1.3）：记录探针位置，供拓扑按位置归纳
	if s.d.Store != nil {
		_ = s.d.Store.UpsertProbe(&model.Probe{
			ProbeID:  report.ProbeID,
			Name:     report.Name,
			Location: location,
			LastSeen: time.Now(),
		})
	}

	sessions := s.syncTopology()
	events := s.evaluateAsync()
	s.d.Reviewer.Audit(s.actor(c), "ingest_probe", report.ProbeID,
		"accepted="+strconv.Itoa(accepted))
	c.JSON(http.StatusOK, gin.H{
		"accepted":   accepted,
		"total":      len(report.Packets) + len(report.Flows),
		"sessions":   sessions,
		"new_events": events,
	})
}

// probeFlow 探针上报的会话子集（§10.6 flows 元素）。
type probeFlow struct {
	SrcIP               string `json:"src_ip"`
	DstIP               string `json:"dst_ip"`
	SrcPort             uint16 `json:"src_port"`
	DstPort             uint16 `json:"dst_port"`
	Proto               string `json:"proto"`
	MAC                 string `json:"mac"`
	DstMAC              string `json:"dst_mac"`
	BytesUp             int64  `json:"bytes_up"`
	BytesDown           int64  `json:"bytes_down"`
	Packets             int64  `json:"packets"`
	FirstSeen           string `json:"first_seen"`
	LastSeen            string `json:"last_seen"`
	SNI                 string `json:"sni"`
	HTTPHost            string `json:"http_host"`
	JA3                 string `json:"ja3"`
	JA4                 string `json:"ja4"`
	IsLongConn          bool   `json:"is_long_conn"`
	HeartbeatIntervalMs int64  `json:"heartbeat_interval_ms"`
	Location            string `json:"location"`
	// 七层转发链（V1.8）：探针自己做 HTTP 解析时可直接上报，优先级高于载荷反解。
	XFF     []string `json:"xff"`
	XRealIP string   `json:"x_real_ip"`
}

// toPackets 将 flow 转成合成上下行报文（长度按字节量折算，保留时间戳）。
func (f *probeFlow) toPackets(baseTs time.Time) (*parser.PacketInfo, *parser.PacketInfo) {
	if f.SrcIP == "" || f.DstIP == "" {
		return nil, nil
	}
	first := baseTs
	last := baseTs
	if t, err := time.Parse(time.RFC3339, f.FirstSeen); err == nil {
		first = t
	}
	if t, err := time.Parse(time.RFC3339, f.LastSeen); err == nil {
		last = t
	}
	proto := f.Proto
	if proto == "" {
		proto = "tcp"
	}
	mkPkt := func(src string, srcPort uint16, dst string, dstPort uint16, length int64, ts time.Time) *parser.PacketInfo {
		return &parser.PacketInfo{
			Timestamp: ts,
			SrcMAC:    f.MAC,
			DstMAC:    f.DstMAC,
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Proto:     proto,
			Length:    int(length),
			// 预解析会话元数据直接贯通（修复探针 TLS 指纹丢失）
			SNI:                 f.SNI,
			HTTPHost:            f.HTTPHost,
			JA3:                 f.JA3,
			JA4:                 f.JA4,
			IsLongConn:          f.IsLongConn,
			HeartbeatIntervalMs: f.HeartbeatIntervalMs,
			Location:            f.Location,
			XFF:                 f.XFF,
			XRealIP:             f.XRealIP,
		}
	}
	upLen := f.BytesUp
	if upLen <= 0 {
		upLen = f.Packets * 400 // 无字节数时粗略折算，避免被降噪吞掉
	}
	up := mkPkt(f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, upLen, first)
	var down *parser.PacketInfo
	if f.BytesDown > 0 {
		down = mkPkt(f.DstIP, f.DstPort, f.SrcIP, f.SrcPort, f.BytesDown, last)
		down.SrcMAC, down.DstMAC = f.DstMAC, f.MAC
	} else if last.After(first) {
		// 保活：用 1 字节小包携带 LastSeen，让聚合器算出时长
		down = mkPkt(f.DstIP, f.DstPort, f.SrcIP, f.SrcPort, 1, last)
		down.SrcMAC, down.DstMAC = f.DstMAC, f.MAC
	}
	return up, down
}

// ---------- 数据接入 ----------

// ingestPCAP PCAP/PCAPNG multipart 上传（SPEC §10.8：200MB 上限）。
func (s *Server) ingestPCAP(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxPCAPUpload)
	fh, err := c.FormFile("file")
	if err != nil {
		fail(c, http.StatusBadRequest, "读取上传文件失败（超过 200MB 上限或非 multipart）: "+err.Error())
		return
	}
	if fh.Size > MaxPCAPUpload {
		fail(c, http.StatusRequestEntityTooLarge, "文件超过 200MB 上限")
		return
	}
	f, err := fh.Open()
	if err != nil {
		fail(c, http.StatusBadRequest, "打开上传文件失败: "+err.Error())
		return
	}
	defer f.Close()

	src, err := ingest.OpenPCAPReader(f)
	if err != nil {
		fail(c, http.StatusBadRequest, "解析失败（非 PCAP/PCAPNG 或文件损坏）: "+err.Error())
		return
	}
	atomic.AddInt32(&s.ingestInFlight, 1)
	defer atomic.AddInt32(&s.ingestInFlight, -1)

	var packets int64
	for p := range src {
		if s.d.Aggregator != nil {
			s.d.Aggregator.Ingest(p)
		}
		packets++
	}
	atomic.AddInt64(&s.packetsTotal, packets)

	sessions := s.syncTopology()
	events := s.evaluateAsync()

	s.d.Reviewer.Audit(s.actor(c), "ingest_pcap", fh.Filename,
		"packets="+strconv.FormatInt(packets, 10)+" sessions="+strconv.Itoa(sessions))
	c.JSON(http.StatusOK, gin.H{
		"filename":    fh.Filename,
		"packets":     packets,
		"sessions":    sessions,
		"new_events":  events,
		"ingested_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// syncTopology 把聚合器会话增量灌入拓扑引擎并持久化新会话，返回会话总数。
func (s *Server) syncTopology() int {
	if s.d.Aggregator == nil {
		return 0
	}
	res := s.d.Aggregator.DrainNow()
	for i := range res.Entries {
		e := &res.Entries[i]
		s.d.Engine.Ingest(&e.Session)
		// 首次抽出才落库：去重判定已收敛在聚合器内部（V1.0），
		// 外层不再维护 savedSessions 这张只会越长越大的表。
		if e.First && s.d.Store != nil {
			_, _ = s.d.Store.SaveSession(&e.Session)
		}
	}
	sessions := res.Sessions()
	// 流量角度：提取内网主机端口（V1.2）
	s.extractPortsFromSessions(sessions)
	// 节点 → 资产同步（账外资产自动登记，V1.2）
	s.syncAssets()
	return len(sessions)
}

// evaluateAsync 同步执行一轮检测评估，返回新建事件数。
func (s *Server) evaluateAsync() int {
	if s.d.Detector == nil {
		return 0
	}
	created, err := s.d.Detector.Evaluate()
	if err != nil {
		return 0
	}
	return len(created)
}

// CountPacket 抓包来源计数（main 抓包泵调用）。
func (s *Server) CountPacket(n int64) {
	atomic.AddInt64(&s.packetsTotal, n)
	atomic.AddInt64(&s.capPackets, n)
}

// CountProbePacket 探针来源计数。
func (s *Server) CountProbePacket(n int64) { atomic.AddInt64(&s.packetsTotal, n) }

// ---------- 抓包控制（§10.6） ----------

func (s *Server) captureStart(c *gin.Context) {
	s.mu.Lock()
	if s.capRunning {
		s.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"Running": true, "Interfaces": s.capIfaces, "message": "抓包已在运行"})
		return
	}
	s.mu.Unlock()

	ifaces := s.d.Cfg.CaptureInterfaces
	if len(ifaces) == 0 {
		fail(c, http.StatusBadRequest, "未配置抓包网卡（capture_interfaces）")
		return
	}
	src, err := ingest.StartCapture(ifaces, s.d.Cfg.CaptureBPF)
	if err != nil {
		if errors.Is(err, ingest.ErrNotEnabled) {
			fail(c, http.StatusNotImplemented, err.Error())
			return
		}
		fail(c, http.StatusInternalServerError, "启动抓包失败: "+err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.capCancel = cancel
	s.capRunning = true
	s.capIfaces = append([]string(nil), ifaces...)
	s.mu.Unlock()
	go func() {
		for p := range src {
			if s.d.Aggregator != nil {
				s.d.Aggregator.Ingest(p)
			}
			s.CountPacket(1)
		}
	}()
	_ = ctx
	s.d.Reviewer.Audit(s.actor(c), "capture_start", strings.Join(ifaces, ","), "")
	c.JSON(http.StatusOK, gin.H{"Running": true, "Interfaces": ifaces})
}

func (s *Server) captureStop(c *gin.Context) {
	s.mu.Lock()
	running := s.capRunning
	if running && s.capCancel != nil {
		s.capCancel()
	}
	s.capRunning = false
	s.capCancel = nil
	s.mu.Unlock()
	s.d.Reviewer.Audit(s.actor(c), "capture_stop", "", "")
	c.JSON(http.StatusOK, gin.H{"Running": false, "was_running": running})
}

func (s *Server) captureStatus(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"Running":    s.capRunning,
		"Interfaces": s.capIfaces,
		"Packets":    s.capPackets,
		"Available":  ingest.CaptureAvailable(),
	})
}

// ---------- 主动探测 ----------

func (s *Server) triggerProbe(c *gin.Context) {
	var body struct {
		Type   string `json:"type"`
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	res, err := s.d.Scanner.Trigger(body.Type, body.Target)
	switch {
	case errors.Is(err, probe.ErrDisabled):
		fail(c, http.StatusForbidden, err.Error())
		return
	case err != nil && res == nil:
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "probe_trigger", body.Type, body.Target)
	// 探测执行但部分失败（如降级路径）仍返回结果 + 说明
	c.JSON(http.StatusOK, res)
}

// ---------- 配置 ----------

// getConfig 输出当前配置（含前端别名键）。
func (s *Server) getConfig(c *gin.Context) {
	cfg := s.d.Cfg
	c.JSON(http.StatusOK, s.configToMap(cfg))
}

// configToMap 输出当前配置（含前端别名键）。
// metrics_enabled 额外与「进程内是否真的挂了指标集合」做与运算：
// 只报配置值会让前端显示"已开启"但 /metrics 实际 404。
func (s *Server) configToMap(cfg *model.SystemConfig) gin.H {
	return gin.H{
		"probe_enabled":                cfg.ProbeEnabled,
		"capture_enabled":              cfg.CaptureEnabled,
		"capture_interfaces":           cfg.CaptureInterfaces,
		"interfaces":                   cfg.CaptureInterfaces, // 前端别名
		"capture_bpf":                  cfg.CaptureBPF,
		"aging_seconds":                cfg.AgingSeconds,
		"aggregate_threshold":          cfg.AggregateThreshold,
		"noise_bytes":                  cfg.NoiseBytes,
		"noise_min_bytes":              cfg.NoiseBytes, // 前端别名
		"noise_packets":                cfg.NoisePackets,
		"noise_min_packets":            cfg.NoisePackets, // 前端别名
		"noise_duration_sec":           cfg.NoiseDurationSec,
		"reverse_proxy_hosts":          cfg.ReverseProxyHosts,
		"reverse_proxy_host_threshold": cfg.ReverseProxyHosts, // 前端别名
		"long_conn_seconds":            cfg.LongConnSeconds,
		"heartbeat_max_bytes":          cfg.HeartbeatMaxBytes,
		"listen_addr":                  cfg.ListenAddr,
		"http_listen":                  cfg.ListenAddr, // 前端别名
		"db_path":                      cfg.DBPath,
		"probe_token_set":              cfg.ProbeToken != "", // 不回显明文
		"audit_retention_days":         cfg.AuditRetentionDays,
		"unarchived_offline_hours":     cfg.UnarchivedOfflineHours,
		"archive_offline_seconds":      cfg.ArchiveOfflineSeconds,
		"scan_ports":                   cfg.ScanPorts,
		"scan_rate":                    cfg.ScanRate,
		// 主动发现（1.2）
		"discover_enabled":          cfg.DiscoverEnabled,
		"discover_profile":          cfg.DiscoverProfile,
		"discover_rate_pps":         cfg.DiscoverRatePPS,
		"discover_concurrency":      cfg.DiscoverConcurrency,
		"discover_timeout_ms":       cfg.DiscoverTimeoutMS,
		"discover_fingerprint":      cfg.DiscoverFingerprint,
		"discover_max_fingerprints": cfg.DiscoverMaxFP,
		"discover_window":           cfg.DiscoverWindow,
		"discover_sec":              cfg.DiscoverSec,
		"discover_cidrs":            cfg.DiscoverCIDRs,
		// 自动发现（V1.4）
		"auto_discovery_enabled":           cfg.AutoDiscoveryEnabled,
		"auto_discovery_sec":               cfg.AutoDiscoverySec,
		"auto_discovery_cidrs":             cfg.AutoDiscoveryCIDRs,
		"auto_discovery_method":            cfg.AutoDiscoveryMethod,
		"auto_discovery_follow_discovered": cfg.AutoDiscoveryFollowDiscovered,
		"auto_discovery_exclude_cidrs":     cfg.AutoDiscoveryExcludeCIDRs,
		"auto_discovery_max_cidrs":         cfg.AutoDiscoveryMaxCIDRs,
		// 会话表容量治理（V1.0）
		"session_max_count":       cfg.SessionMaxCount,
		"session_idle_seconds":    cfg.SessionIdleSeconds,
		"session_max_age_seconds": cfg.SessionMaxAgeSeconds,
		// 可观测性（V1.0）
		"log_level":         cfg.LogLevel,
		"log_format":        cfg.LogFormat,
		"metrics_enabled":   cfg.MetricsEnabled && s.d.Metrics != nil,
		"metrics_token_set": cfg.MetricsToken != "", // 同样不回显明文
	}
}

func numFrom(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case float64:
				return t, true
			case string:
				if f, err := strconv.ParseFloat(t, 64); err == nil {
					return f, true
				}
			}
		}
	}
	return 0, false
}

func strFrom(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func listFrom(m map[string]any, keys ...string) ([]string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case []any:
				out := make([]string, 0, len(t))
				for _, e := range t {
					if s, ok := e.(string); ok {
						out = append(out, s)
					}
				}
				return out, true
			case string: // 前端 textarea 可能按行分隔
				lines := strings.Split(t, "\n")
				out := lines[:0]
				for _, l := range lines {
					if s := strings.TrimSpace(l); s != "" {
						out = append(out, s)
					}
				}
				return out, true
			}
		}
	}
	return nil, false
}

// putConfig 更新配置并持久化（审计 + 引擎/探测器联动）。
func (s *Server) putConfig(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		fail(c, http.StatusBadRequest, "读取请求体失败")
		return
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		fail(c, http.StatusBadRequest, "JSON 解析失败: "+err.Error())
		return
	}
	cfg := s.d.Cfg

	if v, ok := m["probe_enabled"].(bool); ok {
		cfg.ProbeEnabled = v
		s.d.Scanner.SetEnabled(v)
	}
	if v, ok := m["capture_enabled"].(bool); ok {
		cfg.CaptureEnabled = v
	}
	if v, ok := listFrom(m, "capture_interfaces", "interfaces"); ok {
		cfg.CaptureInterfaces = v
	}
	if v, ok := strFrom(m, "capture_bpf"); ok {
		cfg.CaptureBPF = v
	}
	if v, ok := numFrom(m, "aging_seconds"); ok && v > 0 {
		cfg.AgingSeconds = int64(v)
	}
	if v, ok := numFrom(m, "aggregate_threshold"); ok && v > 0 {
		cfg.AggregateThreshold = int(v)
	}
	if v, ok := numFrom(m, "noise_bytes", "noise_min_bytes"); ok && v > 0 {
		cfg.NoiseBytes = int64(v)
	}
	if v, ok := numFrom(m, "noise_packets", "noise_min_packets"); ok && v > 0 {
		cfg.NoisePackets = int64(v)
	}
	if v, ok := numFrom(m, "noise_duration_sec"); ok && v > 0 {
		cfg.NoiseDurationSec = int64(v)
	}
	if v, ok := numFrom(m, "reverse_proxy_hosts", "reverse_proxy_host_threshold"); ok && v > 0 {
		cfg.ReverseProxyHosts = int(v)
	}
	if v, ok := numFrom(m, "long_conn_seconds"); ok && v > 0 {
		cfg.LongConnSeconds = int64(v)
	}
	if v, ok := numFrom(m, "heartbeat_max_bytes"); ok && v > 0 {
		cfg.HeartbeatMaxBytes = int(v)
	}
	if v, ok := strFrom(m, "probe_token"); ok && v != "" {
		// P0-3：空串忽略，避免前端留空时静默清空已设置的令牌。
		cfg.ProbeToken = v
	}
	if v, ok := numFrom(m, "audit_retention_days"); ok && v > 0 {
		cfg.AuditRetentionDays = int(v)
	}
	if v, ok := numFrom(m, "unarchived_offline_hours"); ok && v >= 0 {
		cfg.UnarchivedOfflineHours = int(v)
	}
	if v, ok := numFrom(m, "archive_offline_seconds"); ok && v > 0 {
		cfg.ArchiveOfflineSeconds = int64(v)
	}
	if v, ok := strFrom(m, "scan_ports"); ok && v != "" {
		cfg.ScanPorts = v
	}
	if v, ok := strFrom(m, "scan_rate"); ok && v != "" {
		cfg.ScanRate = v
	}
	// 自动发现（V1.4）
	if v, ok := m["auto_discovery_enabled"].(bool); ok {
		cfg.AutoDiscoveryEnabled = v
	}
	if v, ok := numFrom(m, "auto_discovery_sec"); ok {
		cfg.AutoDiscoverySec = int64(v)
	}
	if v, ok := strFrom(m, "auto_discovery_method"); ok && v != "" {
		cfg.AutoDiscoveryMethod = v
	}
	if v, ok := strFrom(m, "auto_discovery_cidrs"); ok {
		// 逗号分隔的网段列表，如 "10.10.1.0/24,172.16.5.0/24"
		var list []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		if len(list) > 0 {
			cfg.AutoDiscoveryCIDRs = list
		}
	}
	// V1.5 新网段自动跟随
	if v, ok := m["auto_discovery_follow_discovered"].(bool); ok {
		cfg.AutoDiscoveryFollowDiscovered = v
	}
	if v, ok := numFrom(m, "auto_discovery_max_cidrs"); ok {
		cfg.AutoDiscoveryMaxCIDRs = int(v)
	}
	if v, ok := strFrom(m, "auto_discovery_exclude_cidrs"); ok {
		var list []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		if len(list) > 0 {
			cfg.AutoDiscoveryExcludeCIDRs = list
		}
	}
	// 主动发现（1.2）
	if v, ok := m["discover_enabled"].(bool); ok {
		cfg.DiscoverEnabled = v
	}
	if v, ok := strFrom(m, "discover_profile"); ok && v != "" {
		cfg.DiscoverProfile = v
	}
	if v, ok := numFrom(m, "discover_rate_pps"); ok && v >= 0 {
		cfg.DiscoverRatePPS = int(v)
	}
	if v, ok := numFrom(m, "discover_concurrency"); ok && v > 0 {
		cfg.DiscoverConcurrency = int(v)
	}
	if v, ok := numFrom(m, "discover_timeout_ms"); ok && v > 0 {
		cfg.DiscoverTimeoutMS = int(v)
	}
	if v, ok := m["discover_fingerprint"].(bool); ok {
		cfg.DiscoverFingerprint = v
	}
	if v, ok := numFrom(m, "discover_max_fingerprints"); ok && v > 0 {
		cfg.DiscoverMaxFP = int(v)
	}
	if v, ok := strFrom(m, "discover_window"); ok {
		// 允许清空（=全天），但填了就必须是合法窗口，否则会在半夜静默不扫描
		if v == "" {
			cfg.DiscoverWindow = ""
		} else if _, werr := probe.ParseWindow(v); werr != nil {
			fail(c, http.StatusBadRequest, werr.Error())
			return
		} else {
			cfg.DiscoverWindow = v
		}
	}
	if v, ok := numFrom(m, "discover_sec"); ok && v >= 0 {
		cfg.DiscoverSec = int64(v)
	}
	if list, ok := listFrom(m, "discover_cidrs"); ok {
		// 前端可能是 textarea 按行、也可能是逗号分隔的一行；统一拆开再存
		out := make([]string, 0, len(list))
		for _, item := range list {
			for _, c := range strings.Split(item, ",") {
				if c = strings.TrimSpace(c); c != "" {
					out = append(out, c)
				}
			}
		}
		cfg.DiscoverCIDRs = out
	}
	// 速率上限立即生效：用户把它从 800 调到 100，不该等重启才变安全
	if s.d.Scanner != nil && cfg.DiscoverRatePPS >= 0 {
		s.d.Scanner.SetRate(cfg.DiscoverRatePPS)
	}
	// 会话表容量治理（V1.0）：改完立即生效，无需重启
	if v, ok := numFrom(m, "session_max_count"); ok && v > 0 {
		cfg.SessionMaxCount = int(v)
	}
	if v, ok := numFrom(m, "session_idle_seconds"); ok && v > 0 {
		cfg.SessionIdleSeconds = int64(v)
	}
	if v, ok := numFrom(m, "session_max_age_seconds"); ok && v > 0 {
		cfg.SessionMaxAgeSeconds = int64(v)
	}
	if s.d.Aggregator != nil {
		s.d.Aggregator.SetLimits(cfg.SessionMaxCount, cfg.SessionIdleSeconds, cfg.SessionMaxAgeSeconds)
	}
	// 可观测性（V1.0）：日志级别改完立即生效（LevelVar），不需要重启。
	// 日志格式与 /metrics 开关涉及 Handler / 路由注册，只能落盘等下次启动——
	// 这里显式不处理，前端提交后回显仍是旧值，避免"看着改了其实没变"。
	if v, ok := strFrom(m, "log_level"); ok && v != "" {
		cfg.LogLevel = v
		logging.SetLevel(v)
	}
	if v, ok := strFrom(m, "log_format"); ok && v != "" {
		cfg.LogFormat = v
	}
	if v, ok := strFrom(m, "metrics_token"); ok && v != "" {
		// 与 probe_token 同策略：空串忽略，避免前端留空把已设令牌清掉。
		cfg.MetricsToken = v
	}

	// 联动拓扑引擎与检测器
	s.d.Engine.UpdateConfig(*cfg)
	s.d.Detector.UpdateConfig(*cfg)
	if s.d.PersistConfig != nil {
		if err := s.d.PersistConfig(*cfg); err != nil {
			fail(c, http.StatusInternalServerError, "配置持久化失败: "+err.Error())
			return
		}
	}
	s.d.Reviewer.Audit(s.actor(c), "config_update", "system_config", "")
	c.JSON(http.StatusOK, s.configToMap(cfg))
}

// ---------- 审计 ----------

type auditJSON struct {
	ID        int64  `json:"ID"`
	Actor     string `json:"Actor"`
	Action    string `json:"Action"`
	Target    string `json:"Target"`
	Detail    string `json:"Detail"`
	CreatedAt string `json:"CreatedAt"`
}

func (s *Server) listAudit(c *gin.Context) {
	limit := 500
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	logs, err := s.d.Store.ListAuditLogs(limit)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]auditJSON, 0, len(logs))
	for _, l := range logs {
		out = append(out, auditJSON{
			ID: l.ID, Actor: l.Actor, Action: l.Action, Target: l.Target,
			Detail: l.Detail, CreatedAt: l.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, out)
}

// ---------- 静态文件 ----------

func (s *Server) staticHandler(c *gin.Context) {
	path := strings.TrimPrefix(c.Request.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	// 未匹配的 API 路径返回 JSON 404，绝不 SPA 兜底返回 HTML。
	// 否则前端 fetch 拿到 index.html 后 JSON.parse 会抛 "Unexpected token '<'"。
	if path == "api" || strings.HasPrefix(path, "api/") {
		fail(c, http.StatusNotFound, "接口不存在: "+c.Request.URL.Path)
		return
	}
	// 防目录穿越
	if strings.Contains(path, "..") {
		fail(c, http.StatusBadRequest, "非法路径")
		return
	}
	data, err := web.FS.ReadFile(path)
	if err != nil {
		// 静态资源文件不存在 → 404，绝不 fallback 成 HTML（浏览器会把 HTML 当 JS/CSS 执行报错）
		if isStaticAsset(path) {
			fail(c, http.StatusNotFound, "资源不存在: "+path)
			return
		}
		// SPA 兜底到首页
		data, err = web.FS.ReadFile("index.html")
		if err != nil {
			fail(c, http.StatusNotFound, "资源不存在")
			return
		}
		path = "index.html"
	}
	ctype := "text/html; charset=utf-8"
	switch {
	case strings.HasSuffix(path, ".js"):
		ctype = "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		ctype = "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".png"):
		ctype = "image/png"
	case strings.HasSuffix(path, ".svg"):
		ctype = "image/svg+xml"
	}
	c.Data(http.StatusOK, ctype, data)
}

// isStaticAsset 判断路径是否为静态资源文件（存在性未匹配时直接 404，不做 SPA 兜底）。
func isStaticAsset(path string) bool {
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".json"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// ---------- 主机资产库（V1.2） ----------

// syncAssets 把拓扑引擎节点同步为资产（未登记的自动成为"账外资产"）。
// 仅同步内网主机节点，跳过 ext: 外部聚合节点。
func (s *Server) syncAssets() {
	if s.d.Engine == nil || s.d.Store == nil {
		return
	}
	// V1.4 P0 修复：改用 AllNodes 遍历全量内网节点。
	// 此前用 Snapshot 会把"已聚合 /24 网段"的成员节点隐藏掉，导致
	// 网段内超过聚合阈值的主机永远进不了资产库（账外资产发现静默失效）。
	nodes := s.d.Engine.AllNodes()
	now := time.Now()
	for i := range nodes {
		n := &nodes[i]
		if n.NodeKey == "" || strings.HasPrefix(n.NodeKey, "ext:") {
			continue
		}
		existing, err := s.d.Store.AssetByKey(n.NodeKey)
		if err != nil {
			continue
		}
		if existing == nil {
			// 新发现主机 → 登记为账外资产（未归档）
			// Location 先取探针位置，让用户能看到"这台设备从哪个位置被看到"；
			// 后续归档登记时由用户填写真实物理位置覆盖。
			a := &model.Asset{
				NodeKey:   n.NodeKey,
				IPs:       n.IPs,
				MAC:       n.MAC,
				Status:    model.AssetUnarchived,
				Location:  n.Location,
				FirstSeen: n.FirstSeen,
				LastSeen:  n.LastSeen,
				CreatedAt: now,
				UpdatedAt: now,
			}
			_, _ = s.d.Store.UpsertAsset(a)
		} else {
			// 已存在 → 刷新 IP/MAC/last_seen
			existing.IPs = n.IPs
			existing.MAC = n.MAC
			existing.LastSeen = n.LastSeen
			// 未归档资产跟随探针位置；已归档资产保留用户填写的物理位置，不覆盖
			if existing.Status == model.AssetUnarchived && n.Location != "" {
				existing.Location = n.Location
			}
			_, _ = s.d.Store.UpsertAsset(existing)
		}
	}
}

// assetJSON 资产列表 DTO（含在线状态）。
func (s *Server) assetJSON(a model.Asset) gin.H {
	online := false
	offlineSec := s.d.Cfg.ArchiveOfflineSeconds
	if offlineSec <= 0 {
		offlineSec = 600
	}
	if time.Since(a.LastSeen) < time.Duration(offlineSec)*time.Second {
		online = true
	}
	return gin.H{
		"id":          a.ID,
		"node_key":    a.NodeKey,
		"ips":         a.IPs,
		"mac":         a.MAC,
		"hostname":    a.Hostname,
		"os":          a.OS,
		"status":      a.Status,
		"owner":       a.Owner,
		"department":  a.Department,
		"location":    a.Location,
		"description": a.Description,
		"first_seen":  a.FirstSeen.UTC().Format(time.RFC3339),
		"last_seen":   a.LastSeen.UTC().Format(time.RFC3339),
		"online":      online,
		"archived_at": orEmpty(a.ArchivedAt),
		"archived_by": a.ArchivedBy,
	}
}

func orEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------- 资产台账对照（V1.7） ----------

// ledgerMaxBytes 台账 CSV 上限（5 万行约 6MB，留一倍余量）。
const ledgerMaxBytes = 16 << 20

// collectLedgerHosts 把系统已发现的主机整理成对照用的 Host 列表。
// 以资产库为准（资产库由 AllNodes 同步，已含被聚合网段折叠的主机，见 V1.4 P0），
// 风险等级从拓扑节点补充——账外设备里"有没有高风险的"才是排查优先级的关键。
func (s *Server) collectLedgerHosts() []ledger.Host {
	s.syncAssets()
	assets, err := s.d.Store.ListAssets("")
	if err != nil {
		return nil
	}
	risk := map[string]string{}
	if s.d.Engine != nil {
		for _, n := range s.d.Engine.AllNodes() {
			if n.NodeKey != "" {
				risk[n.NodeKey] = n.RiskLevel
			}
		}
	}
	offlineSec := s.d.Cfg.ArchiveOfflineSeconds
	if offlineSec <= 0 {
		offlineSec = 600
	}
	out := make([]ledger.Host, 0, len(assets))
	for _, a := range assets {
		out = append(out, ledger.Host{
			NodeKey:    a.NodeKey,
			IPs:        a.IPs,
			MAC:        a.MAC,
			Hostname:   a.Hostname,
			OS:         a.OS,
			Online:     time.Since(a.LastSeen) < time.Duration(offlineSec)*time.Second,
			Department: a.Department,
			Owner:      a.Owner,
			Location:   a.Location,
			RiskLevel:  risk[a.NodeKey],
			LastSeen:   a.LastSeen,
			Archived:   a.Status == model.AssetArchived,
		})
	}
	return out
}

// ledgerImport 导入台账 CSV。支持三种提交方式（都为"全量替换"语义）：
//  1. multipart/form-data 带 file 字段（浏览器上传）
//  2. application/json  {"csv":"...","batch":"..."}（粘贴文本）
//  3. text/csv 原始正文（curl / 脚本）
func (s *Server) ledgerImport(c *gin.Context) {
	if s.d.Store == nil {
		fail(c, http.StatusServiceUnavailable, "存储未就绪")
		return
	}
	var (
		rdr   io.Reader = http.MaxBytesReader(c.Writer, c.Request.Body, ledgerMaxBytes)
		batch           = "手动导入"
	)
	switch ct := c.ContentType(); {
	case strings.HasPrefix(ct, "multipart/form-data"):
		fh, err := c.FormFile("file")
		if err != nil {
			fail(c, http.StatusBadRequest, "缺少 file 字段（请选择 CSV 文件）")
			return
		}
		f, err := fh.Open()
		if err != nil {
			fail(c, http.StatusBadRequest, "读取上传文件失败："+err.Error())
			return
		}
		defer f.Close()
		rdr = f
		if fh.Filename != "" {
			batch = fh.Filename
		}
	case ct == "application/json":
		var body struct {
			CSV   string `json:"csv"`
			Batch string `json:"batch"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			fail(c, http.StatusBadRequest, "JSON 解析失败："+err.Error())
			return
		}
		rdr = strings.NewReader(body.CSV)
		if strings.TrimSpace(body.Batch) != "" {
			batch = body.Batch
		}
	}

	entries, st, err := ledger.ParseCSV(rdr, batch)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.d.Store.ReplaceLedger(entries)
	if err != nil {
		fail(c, http.StatusInternalServerError, "写入台账失败："+err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "ledger_import", batch,
		fmt.Sprintf("导入 %d 条，跳过 %d 行", n, st.Skipped))
	c.JSON(http.StatusOK, gin.H{
		"imported": n,
		"skipped":  st.Skipped,
		"rows":     st.Rows,
		"batch":    batch,
	})
}

// listLedger 台账条目列表。
func (s *Server) listLedger(c *gin.Context) {
	entries, err := s.d.Store.ListLedger()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []model.LedgerEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries, "total": len(entries)})
}

// clearLedger 清空台账。
func (s *Server) clearLedger(c *gin.Context) {
	n, err := s.d.Store.ClearLedger()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "ledger_clear", "all", fmt.Sprintf("清空 %d 条台账", n))
	c.JSON(http.StatusOK, gin.H{"deleted": n})
}

// ledgerDiff 台账 ↔ 拓扑观测 的三方对照（在册在网 / 台账外 / 台账僵尸 / IP 不符）。
func (s *Server) ledgerDiff(c *gin.Context) {
	entries, err := s.d.Store.ListLedger()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	hosts := s.collectLedgerHosts()
	res := ledger.Diff(entries, hosts)
	res.Summary.LedgerTotal = len(entries)
	res.Summary.HostTotal = len(hosts)
	c.JSON(http.StatusOK, res)
}

// ---------- 七层转发识别（V1.8） ----------

// listProxies 返回已识别的七层转发节点（nginx/HAProxy/SLB/API 网关）及其背后真实客户端。
// 这些客户端被动侧看不到直连流量，只能靠 X-Forwarded-For 还原——不识别就等于不存在。
func (s *Server) listProxies(c *gin.Context) {
	if s.d.Engine == nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	proxies := s.d.Engine.Proxies()
	if proxies == nil {
		proxies = []topology.ProxyInfo{}
	}
	totalClients := 0
	for _, p := range proxies {
		totalClients += p.Clients
	}
	c.JSON(http.StatusOK, gin.H{
		"proxies": proxies,
		"total":   len(proxies),
		"clients": totalClients,
	})
}

func (s *Server) listAssets(c *gin.Context) {
	s.syncAssets() // 列表前先同步一次，保证新节点即时可见
	status := c.Query("status")
	assets, err := s.d.Store.ListAssets(status)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]gin.H, 0, len(assets))
	for _, a := range assets {
		out = append(out, s.assetJSON(a))
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) assetStats(c *gin.Context) {
	s.syncAssets()
	assets, err := s.d.Store.ListAssets("")
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	var total, archived, unarchived, online, offline int
	for _, a := range assets {
		total++
		if a.Status == model.AssetArchived {
			archived++
		} else {
			unarchived++
		}
		if s.assetJSON(a)["online"].(bool) {
			online++
		} else {
			offline++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"total":      total,
		"archived":   archived,
		"unarchived": unarchived, // 账外资产
		"online":     online,
		"offline":    offline,
	})
}

func (s *Server) archiveAsset(c *gin.Context) {
	var body struct {
		NodeKey     string `json:"node_key"`
		Owner       string `json:"owner"`
		Department  string `json:"department"`
		Location    string `json:"location"`
		Hostname    string `json:"hostname"`
		OS          string `json:"os"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if body.NodeKey == "" {
		fail(c, http.StatusBadRequest, "缺少 node_key")
		return
	}
	if err := s.d.Store.ArchiveAsset(body.NodeKey, body.Owner, body.Department, body.Location, body.Hostname, body.OS, body.Description, s.actor(c)); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "asset_archive", body.NodeKey,
		"owner="+body.Owner+" dept="+body.Department)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) updateAsset(c *gin.Context) {
	key := c.Param("key")
	var body struct {
		Owner       string `json:"owner"`
		Department  string `json:"department"`
		Location    string `json:"location"`
		Hostname    string `json:"hostname"`
		OS          string `json:"os"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if err := s.d.Store.UpdateAsset(key, body.Owner, body.Department, body.Location, body.Hostname, body.OS, body.Description); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "asset_update", key, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) deleteAsset(c *gin.Context) {
	key := c.Param("key")
	if err := s.d.Store.DeleteAsset(key); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.d.Store.DeletePortsByKey(key)
	s.d.Reviewer.Audit(s.actor(c), "asset_delete", key, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------- 端口记录（V1.2） ----------

func (s *Server) listPorts(c *gin.Context) {
	ip := c.Query("ip")
	key := c.Query("node_key")
	ports, err := s.d.Store.ListPorts(ip, key)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	type portJSON struct {
		ID       int64  `json:"id"`
		NodeKey  string `json:"node_key"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Proto    string `json:"proto"`
		Service  string `json:"service"`
		State    string `json:"state"`
		Source   string `json:"source"`
		LastSeen string `json:"last_seen"`
		// 服务指纹（1.2）
		Product  string   `json:"product,omitempty"`
		Version  string   `json:"version,omitempty"`
		Title    string   `json:"title,omitempty"`
		Banner   string   `json:"banner,omitempty"`
		TLSCN    string   `json:"tls_cn,omitempty"`
		TLSNames []string `json:"tls_names,omitempty"`
		Favicon  string   `json:"favicon_hash,omitempty"`
	}
	out := make([]portJSON, 0, len(ports))
	for _, p := range ports {
		out = append(out, portJSON{
			ID: p.ID, NodeKey: p.NodeKey, IP: p.IP, Port: p.Port, Proto: p.Proto,
			Service: p.Service, State: p.State, Source: p.Source,
			LastSeen: p.LastSeen.UTC().Format(time.RFC3339),
			Product:  p.Product, Version: p.Version, Title: p.Title, Banner: p.Banner,
			TLSCN: p.TLSCN, TLSNames: p.TLSNames, Favicon: p.Favicon,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) scanPorts(c *gin.Context) {
	var body struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Target == "" {
		fail(c, http.StatusBadRequest, "缺少 target（IP 或 CIDR）")
		return
	}
	if !probe.NmapAvailable(s.d.Cfg.NmapPath) {
		fail(c, http.StatusServiceUnavailable, "未检测到 nmap 命令，无法主动扫描（请在系统配置中设置 nmap_path）")
		return
	}
	s.scanMu.Lock()
	s.scanSeq++
	id := fmt.Sprintf("scan-%d", s.scanSeq)
	task := &scanTask{ID: id, Target: body.Target, Status: "running", Started: time.Now()}
	s.scanTasks[id] = task
	s.scanMu.Unlock()

	// 后台执行（全端口扫描耗时长，不阻塞请求）
	go func() {
		records, err := probe.RunNmapScan(s.d.Cfg.NmapPath, body.Target, s.d.Cfg.ScanPorts, s.d.Cfg.ScanRate)
		s.scanMu.Lock()
		defer s.scanMu.Unlock()
		task.Done = time.Now()
		if err != nil {
			task.Status = "error"
			task.Error = err.Error()
			return
		}
		// 关联 node_key 并落库
		for i := range records {
			r := &records[i]
			if n := s.d.Engine.NodeByIP(r.IP); n != nil {
				r.NodeKey = n.NodeKey
			}
			if r.FirstSeen.IsZero() {
				r.FirstSeen = time.Now()
			}
			_ = s.d.Store.UpsertPort(r)
		}
		task.Status = "done"
		task.Found = len(records)
		s.d.Reviewer.Audit("system", "port_scan", body.Target, "found="+strconv.Itoa(len(records)))
	}()

	s.d.Reviewer.Audit(s.actor(c), "port_scan_start", body.Target, "")
	c.JSON(http.StatusAccepted, gin.H{"task_id": id, "status": "running"})
}

func (s *Server) scanPortsStatus(c *gin.Context) {
	id := c.Param("id")
	s.scanMu.Lock()
	task := s.scanTasks[id]
	s.scanMu.Unlock()
	if task == nil {
		fail(c, http.StatusNotFound, "扫描任务不存在")
		return
	}
	c.JSON(http.StatusOK, task)
}

// ---------- 探针注册（V1.3：按探针位置归纳拓扑） ----------

func (s *Server) listProbes(c *gin.Context) {
	probes, err := s.d.Store.ListProbes()
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	if probes == nil {
		probes = []model.Probe{}
	}
	c.JSON(http.StatusOK, probes)
}

func (s *Server) deleteProbe(c *gin.Context) {
	id := c.Param("id")
	if err := s.d.Store.DeleteProbe(id); err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "probe_delete", id, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// extractPortsFromSessions 从流量会话提取内网主机端口（流量角度，source=traffic）。
func (s *Server) extractPortsFromSessions(sessions []model.Session) {
	if s.d.Store == nil || s.d.Engine == nil {
		return
	}
	var ports []model.PortRecord
	for i := range sessions {
		ses := &sessions[i]
		// 内网主机作为被访问方（服务端）：DstPort 为服务端口
		if topology.IsPrivate(ses.FiveTuple.DstIP) {
			key := ""
			if n := s.d.Engine.NodeByIP(ses.FiveTuple.DstIP); n != nil {
				key = n.NodeKey
			}
			ports = append(ports, model.PortRecord{
				NodeKey:   key,
				IP:        ses.FiveTuple.DstIP,
				Port:      int(ses.FiveTuple.DstPort),
				Proto:     ses.FiveTuple.Proto,
				Source:    model.PortSourceTraffic,
				FirstSeen: ses.FirstSeen,
				LastSeen:  ses.LastSeen,
			})
		}
	}
	if len(ports) > 0 {
		_ = s.d.Store.UpsertPorts(ports)
	}
}
