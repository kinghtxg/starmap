package api

// 站点资产接口（V1.7）。
//
// 站点是 ports 的派生视图（见 store/sites.go）。这一层只负责：
//   - 按筛选条件分页取列表 + 总数（前端本地分页，与端口/资产页一致）；
//   - 概览统计（端口/产品分布、证书到期、自签数量）；
//   - 变更视图（窗口内新增 / 不再活动）；
//   - 人工标注（名称 / 标签 / 备注）——这是唯一会写库的部分。

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/model"
	"starmap/internal/store"
)

// siteFilterFromQuery 从查询参数构造筛选条件。
//
// 抽出来是因为列表、统计、导出三处必须用同一套解析——分别写的话，
// 页面上筛了"自签"，导出来的却是全部，这种不一致用户一定会遇到。
func siteFilterFromQuery(c *gin.Context) store.SiteFilter {
	f := store.SiteFilter{
		Keyword: queryKeyword(c),
		Scheme:  c.Query("scheme"),
		Tag:     strings.TrimSpace(c.Query("tag")),
	}
	if v := c.Query("port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			f.Port = n
		}
	}
	if truthy(c.Query("self_signed")) {
		f.OnlySelfSigned = true
	}
	if truthy(c.Query("expiring")) {
		f.OnlyExpiring = true
	}
	if truthy(c.Query("expired")) {
		f.OnlyExpired = true
	}
	if truthy(c.Query("untagged")) {
		f.OnlyUntagged = true
	}
	if truthy(c.Query("online")) {
		f.OnlineOnly = true
		f.OnlineAfter = time.Now().Add(-store.PortStaleAfter)
	}
	return f
}

// truthy 解析 1/true/yes/on。前端各页传参习惯不统一，与其改一堆前端不如都认。
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// siteJSON 站点给前端的形态。
//
// 不直接把 model.Site 序列化出去：时间要统一成 RFC3339（前端 toLocaleString 依赖它），
// 而 model 里是 time.Time（默认序列化成带纳秒的 RFC3339，前端解析没问题但可读性差）。
type siteJSON struct {
	Key          string   `json:"key"`
	Scheme       string   `json:"scheme"`
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	NodeKey      string   `json:"node_key"`
	Hostname     string   `json:"hostname,omitempty"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	HTTPStatus   int      `json:"http_status,omitempty"`
	Product      string   `json:"product,omitempty"`
	Version      string   `json:"version,omitempty"`
	Location     string   `json:"http_location,omitempty"`
	TLSCN        string   `json:"tls_cn,omitempty"`
	TLSNames     []string `json:"tls_names,omitempty"`
	CertIssuer   string   `json:"cert_issuer,omitempty"`
	CertExpiry   string   `json:"cert_expiry,omitempty"`
	CertDaysLeft int      `json:"cert_days_left"`
	SelfSigned   bool     `json:"self_signed,omitempty"`
	Favicon      string   `json:"favicon_hash,omitempty"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	Online       bool     `json:"online"`
	Name         string   `json:"name,omitempty"`
	Department   string   `json:"department,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Note         string   `json:"note,omitempty"`
	Risk         []string `json:"risk,omitempty"`
}

func toSiteJSON(s *model.Site) siteJSON {
	out := siteJSON{
		Key: s.Key, Scheme: s.Scheme, IP: s.IP, Port: s.Port, NodeKey: s.NodeKey,
		Hostname: s.Hostname, Title: s.Title, Server: s.Server, HTTPStatus: s.Status,
		Product: s.Product, Version: s.Version, Location: s.Location,
		TLSCN: s.TLSCN, TLSNames: s.TLSNames, CertIssuer: s.CertIssuer, CertExpiry: s.CertExpiry,
		CertDaysLeft: s.CertDaysLeft, SelfSigned: s.SelfSigned, Favicon: s.Favicon,
		FirstSeen: s.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:  s.LastSeen.UTC().Format(time.RFC3339),
		Online:    s.Online, Name: s.Name, Department: s.Department,
		Tags: s.Tags, Note: s.Note, Risk: s.Risk,
	}
	return out
}

// listSites GET /api/sites
func (s *Server) listSites(c *gin.Context) {
	f := siteFilterFromQuery(c)
	limit, offset := pageParams(c)
	sites, err := s.d.Store.ListSites(f, limit, offset)
	if err != nil {
		internalError(c, err, "查询站点失败")
		return
	}
	out := make([]siteJSON, 0, len(sites))
	for i := range sites {
		out = append(out, toSiteJSON(&sites[i]))
	}
	if total, cerr := s.d.Store.CountSites(f); cerr == nil {
		setListMeta(c, total, limit)
	}
	c.JSON(http.StatusOK, gin.H{"sites": out, "count": len(out)})
}

// siteStats GET /api/sites/stats
func (s *Server) siteStats(c *gin.Context) {
	st, err := s.d.Store.SiteStats(siteFilterFromQuery(c))
	if err != nil {
		internalError(c, err, "统计站点失败")
		return
	}
	c.JSON(http.StatusOK, st)
}

// listSiteTags GET /api/sites/tags
func (s *Server) listSiteTags(c *gin.Context) {
	tags, err := s.d.Store.ListSiteTags()
	if err != nil {
		internalError(c, err, "查询标签失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// siteDetail GET /api/sites/detail?key=scheme://ip:port
//
// 用查询参数而不是 /sites/:key：站点标识里带 "://" 和 ":"，
// 放进路径段要么被 gin 的通配符规则挡住（与 /sites/stats 冲突），
// 要么得靠前端做两次转义——查询参数没有这些问题。
func (s *Server) siteDetail(c *gin.Context) {
	key := strings.TrimSpace(c.Query("key"))
	if key == "" {
		fail(c, http.StatusBadRequest, "缺少 key 参数（形如 http://10.0.0.1:80）")
		return
	}
	site, err := s.d.Store.GetSite(key)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if site == nil {
		fail(c, http.StatusNotFound, "站点不存在或已下线: "+key)
		return
	}
	// 详情页要一并给出"这台机器上还有哪些端口"，省掉前端再发一次请求。
	ports, perr := s.d.Store.ListPorts(site.IP, "")
	if perr != nil {
		ports = nil
	}
	type portBrief struct {
		Port     int      `json:"port"`
		Proto    string   `json:"proto"`
		State    string   `json:"state"`
		Service  string   `json:"service,omitempty"`
		Product  string   `json:"product,omitempty"`
		Title    string   `json:"title,omitempty"`
		LastSeen string   `json:"last_seen"`
		TLSCN    string   `json:"tls_cn,omitempty"`
		TLSNames []string `json:"tls_names,omitempty"`
	}
	briefs := make([]portBrief, 0, len(ports))
	for _, p := range ports {
		briefs = append(briefs, portBrief{
			Port: p.Port, Proto: p.Proto, State: p.State, Service: p.Service,
			Product: p.Product, Title: p.Title, TLSCN: p.TLSCN, TLSNames: p.TLSNames,
			LastSeen: p.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"site": toSiteJSON(site), "host_ports": briefs})
}

// siteChanges GET /api/sites/changes?days=7
func (s *Server) siteChanges(c *gin.Context) {
	days := 7
	if v := c.Query("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	since := time.Now().AddDate(0, 0, -days)
	added, gone, err := s.d.Store.SiteChanges(since, 500)
	if err != nil {
		internalError(c, err, "查询站点变更失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"days": days, "since": since.UTC().Format(time.RFC3339),
		"added": added, "removed": gone,
		"added_count": len(added), "removed_count": len(gone),
	})
}

// upsertSiteMeta POST /api/sites/meta
//
// 请求体用 `key` 而不是 `site_key`：同一个资源标识在 GET/DELETE 里是 `?key=`，
// 在 POST body 里换成另一个名字，对接方一定会踩（会得到"标识为空"这种
// 看起来像自己写错了的报错）。读写字段必须同名。
func (s *Server) upsertSiteMeta(c *gin.Context) {
	var body struct {
		Key        string   `json:"key"`
		Name       string   `json:"name"`
		Department string   `json:"department"`
		Tags       []string `json:"tags"`
		Note       string   `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	body.Key = strings.TrimSpace(body.Key)
	if !checkField(c, "name", body.Name, maxNameLen) ||
		!checkField(c, "department", body.Department, maxNameLen) ||
		!checkField(c, "note", body.Note, maxDescLen) {
		return
	}
	// 站点必须真实存在才能标注：否则前端手误就能往 site_meta 里塞垃圾行，
	// 而站点是派生视图，这些行永远没有对应的站点。
	site, err := s.d.Store.GetSite(body.Key)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if site == nil {
		fail(c, http.StatusNotFound, "站点不存在或已下线: "+body.Key)
		return
	}
	// 标签数量与单个长度都要限，否则一个超长标签会把站点列表撑变形。
	if len(body.Tags) > 20 {
		fail(c, http.StatusBadRequest, "标签最多 20 个")
		return
	}
	for i, t := range body.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len([]rune(t)) > 32 {
			fail(c, http.StatusBadRequest, "单个标签最长 32 个字符")
			return
		}
		body.Tags[i] = t
	}
	if err := s.d.Store.UpsertSiteMeta(&model.SiteMeta{
		SiteKey: body.Key, Name: body.Name, Department: body.Department,
		Tags: body.Tags, Note: body.Note,
	}); err != nil {
		internalError(c, err, "保存站点标注失败")
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "site_meta_update", body.Key,
		"name="+body.Name+" dept="+body.Department+" tags="+strings.Join(body.Tags, ","))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// deleteSiteMeta DELETE /api/sites/meta?key=...
func (s *Server) deleteSiteMeta(c *gin.Context) {
	key := strings.TrimSpace(c.Query("key"))
	if key == "" {
		fail(c, http.StatusBadRequest, "缺少 key 参数")
		return
	}
	n, err := s.d.Store.DeleteSiteMeta(key)
	if err != nil {
		internalError(c, err, "删除站点标注失败")
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "site_meta_delete", key, "")
	c.JSON(http.StatusOK, gin.H{"ok": true, "deleted": n})
}

// exportSites GET /api/export/sites.csv
func (s *Server) exportSites(c *gin.Context) {
	f := siteFilterFromQuery(c)
	ew, err := newCSV(c, "sites", []string{
		"站点", "协议", "IP", "端口", "名称", "归属单位", "页面标题", "产品", "版本", "Server",
		"状态码", "跳转", "证书CN", "证书SAN", "签发者", "到期日", "剩余天数", "自签",
		"标签", "备注", "风险", "主机名", "首次发现", "最后发现",
	})
	if err != nil {
		return
	}
	defer ew.done()

	for offset := 0; offset < exportMaxRows; offset += exportPageSize {
		list, err := s.d.Store.ListSites(f, exportPageSize, offset)
		if err != nil {
			return
		}
		for i := range list {
			site := &list[i]
			selfSigned := "否"
			if site.SelfSigned {
				selfSigned = "是"
			}
			// 有没有证书情报按 CertExpiry 判，不按 CertDaysLeft >= 0：
			// 后者会把"昨天到期"（-1）当成"无情报"输出空白，
			// CSV 里就看不出这张证书已经过期了。
			daysLeft := ""
			if site.CertExpiry != "" {
				daysLeft = strconv.Itoa(site.CertDaysLeft)
			}
			if !ew.add(
				site.Key, site.Scheme, site.IP, strconv.Itoa(site.Port), site.Name,
				site.Department, site.Title,
				site.Product, site.Version, site.Server, strconv.Itoa(site.Status), site.Location,
				site.TLSCN, strings.Join(site.TLSNames, " "), site.CertIssuer, site.CertExpiry,
				daysLeft, selfSigned, strings.Join(site.Tags, ","), site.Note,
				strings.Join(site.Risk, ","), site.Hostname,
				fmtTime(site.FirstSeen), fmtTime(site.LastSeen),
			) {
				return
			}
		}
		if len(list) < exportPageSize {
			return
		}
	}
}
