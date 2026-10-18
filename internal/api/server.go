// Package api Gin 路由 + 全部 REST API + 静态文件托管（SPEC §6 + §10.6）。
// 注意：前端契约使用 PascalCase 字段、字符串节点 ID（聚合节点 "subnet:<cidr>"），
// API 层负责 model（snake_case）与前端 DTO 的转换。
package api

import (
	"context"
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
	"starmap/internal/ingest"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
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
	// PacketCh 探针上报报文通道（ProbeHandler 写入）
	PacketCh chan *parser.PacketInfo
	// PersistConfig PUT /api/config 持久化钩子
	PersistConfig func(model.SystemConfig) error
	Version       string
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
	savedSessions  map[string]bool
	ingestInFlight int32

	// 端口扫描任务（V1.2）
	scanMu    sync.Mutex
	scanTasks map[string]*scanTask
	scanSeq   int64
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
	s := &Server{d: d, savedSessions: map[string]bool{}, scanTasks: map[string]*scanTask{}}
	if s.d.Version == "" {
		s.d.Version = "V1.0"
	}
	r.Use(gin.Recovery(), s.corsMiddleware())
	// 可选账号系统 / APSSO SSO 门卫（默认 mode=none，不启用时零行为差异，见 docs/AUTH-APSSO.md）
	r.Use(auth.Middleware(d.Cfg.Auth))
	auth.RegisterRoutes(r, d.Cfg.Auth)

	api := r.Group("/api")
	{
		api.GET("/health", s.health)
		api.GET("/topology", s.topologySnapshot)
		api.GET("/topology/subnet/*cidr", s.subnetSnapshot)
		api.GET("/nodes/:id", s.nodeDetail)
		api.GET("/events", s.listEvents)
		api.POST("/events/:id/review", s.reviewEvent)
		api.GET("/whitelist", s.listWhitelist)
		api.POST("/whitelist", s.createWhitelist)
		api.PUT("/whitelist/:id", s.updateWhitelist)
		api.DELETE("/whitelist/:id", s.deleteWhitelist)
		api.GET("/domains", s.listDomains)
		api.POST("/domains", s.createDomain)
		api.PUT("/domains/:id", s.updateDomain)
		api.DELETE("/domains/:id", s.deleteDomain)
		api.POST("/ingest/pcap", s.ingestPCAP)
		api.POST("/ingest/probe", s.ingestProbe)
		api.GET("/config", s.getConfig)
		api.PUT("/config", s.putConfig)
		api.GET("/audit", s.listAudit)
		api.GET("/stats", s.stats)
		api.POST("/probe/trigger", s.triggerProbe)
		api.POST("/capture/start", s.captureStart)
		api.POST("/capture/stop", s.captureStop)
		api.GET("/capture/status", s.captureStatus)
		// 主机资产库 + 端口记录（V1.2）
		api.GET("/assets", s.listAssets)
		api.GET("/assets/stats", s.assetStats)
		api.POST("/assets/archive", s.archiveAsset)
		api.PUT("/assets/:key", s.updateAsset)
		api.DELETE("/assets/:key", s.deleteAsset)
		api.GET("/ports", s.listPorts)
		api.POST("/ports/scan", s.scanPorts)
		api.GET("/ports/scan/:id", s.scanPortsStatus)
		// 探针注册（V1.3：按探针位置归纳拓扑）
		api.GET("/probes", s.listProbes)
		api.DELETE("/probes/:id", s.deleteProbe)
	}

	// 静态资源（embed.FS 单二进制分发）
	r.NoRoute(s.staticHandler)
	return r
}

// Handler 返回 http.Handler（测试用）。
func (s *Server) Handler() http.Handler { return nil }

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

// authPlaceholder 已废弃：认证由 internal/auth.Middleware 承担（默认 mode=none）。
func authPlaceholder() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// actor P0-4：审计日志 Actor 由硬编码 "api" 改为可追溯来源。
// 已启用账号系统时取登录身份，否则取客户端 IP。
func (s *Server) actor(c *gin.Context) string {
	if sub := auth.Subject(c); sub != "" {
		return sub
	}
	return c.ClientIP()
}

// probeTokenMiddleware §10.7：配置 probe_token 则校验（header X-Probe-Token 或 JSON token 字段）。
func (s *Server) probeTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		want := ""
		if s.d.Cfg != nil {
			want = s.d.Cfg.ProbeToken
		}
		if want != "" {
			got := c.GetHeader("X-Probe-Token")
			if got == "" {
				got = c.Query("token")
			}
			if got != want {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "探针 token 校验失败"})
				return
			}
		}
		c.Next()
	}
}

func fail(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"error": msg})
}

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
	sessions := 0
	if s.d.Aggregator != nil {
		sessions = len(s.d.Aggregator.Sessions())
	}
	c.JSON(http.StatusOK, gin.H{
		"NodeCount":     snap.Stats.NodeCount,
		"EdgeCount":     snap.Stats.EdgeCount,
		"ActiveNodes":   snap.Stats.ActiveNodes,
		"ActiveEdges":   snap.Stats.ActiveEdges,
		"TotalBytes":    snap.Stats.TotalBytes,
		"EventCount":    len(events),
		"PendingEvents": pending,
		"SessionCount":  sessions,
		"PacketCount":   atomic.LoadInt64(&s.packetsTotal),
		"Capture":       capSt,
		"GeneratedAt":   time.Now().UTC(),
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
	for i := range snap.Nodes {
		nodes = append(nodes, toNodeJSON(&snap.Nodes[i]))
	}
	vedges := s.d.Engine.SubnetVisibleEdges(cidr)
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
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<20))
	if err != nil {
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
		if got != want {
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
	sessions := s.d.Aggregator.Finalize()
	for i := range sessions {
		ses := &sessions[i]
		s.d.Engine.Ingest(ses)
		key := ses.FiveTuple.Key()
		s.mu.Lock()
		known := s.savedSessions[key]
		if !known {
			s.savedSessions[key] = true
		}
		s.mu.Unlock()
		if !known && s.d.Store != nil {
			_, _ = s.d.Store.SaveSession(ses)
		}
	}
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
	c.JSON(http.StatusOK, configToMap(cfg))
}

func configToMap(cfg *model.SystemConfig) gin.H {
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
	c.JSON(http.StatusOK, configToMap(cfg))
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
			a := &model.Asset{
				NodeKey:   n.NodeKey,
				IPs:       n.IPs,
				MAC:       n.MAC,
				Status:    model.AssetUnarchived,
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
	}
	out := make([]portJSON, 0, len(ports))
	for _, p := range ports {
		out = append(out, portJSON{
			ID: p.ID, NodeKey: p.NodeKey, IP: p.IP, Port: p.Port, Proto: p.Proto,
			Service: p.Service, State: p.State, Source: p.Source,
			LastSeen: p.LastSeen.UTC().Format(time.RFC3339),
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
