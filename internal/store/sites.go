package store

import (
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"starmap/internal/model"
)

// ---------- 站点资产（V1.7） ----------
//
// 站点不是一张独立的表，而是 ports 上的一个**派生视图**：
//
//	站点 = 有 HTTP/S 应用层响应的 open 端口（state='open' 且有状态码/标题/Server/证书）
//
// 为什么不建表：端口是主动扫描与流量两条路共同写入的事实来源，站点只是它的一个
// 观察角度。再存一份就必然出现"端口已经关了但站点还在列表里"的孤儿行，
// 而这种不一致从来不会自己消失（1.6.0 的任务账刻意只记账、不复制扫描结果，
// 同一条理由）。人工标注落 site_meta，扫描重跑不会覆盖人的判断。

// SiteFilter 站点列表筛选条件。
type SiteFilter struct {
	Keyword        string
	Port           int
	Scheme         string // http | https
	Tag            string
	OnlySelfSigned bool
	OnlyExpiring   bool // 30 天内到期
	OnlyExpired    bool
	OnlyUntagged   bool
	OnlineOnly     bool
	// OnlineAfter 在线判据：last_seen 不早于它。零值表示不判定。
	OnlineAfter time.Time
}

// siteBase 是站点派生视图的公共部分（列表、计数、统计共用一份 SQL，
// 三处各写一遍的话，筛选条件稍微一改就会有一处漏掉）。
//
// ROW_NUMBER 的作用：同一个 ip:port 可能因 node_key 不同存在多行
// （同一台机器既被流量看到、又被扫描器以不同 node_key 写入），
// 站点只该出现一次，取 last_seen 最新的那行。
const siteBase = `
WITH site AS (
  SELECT p.ip, p.port, p.proto, p.node_key, p.first_seen, MAX(p.last_seen) AS last_seen,
         p.title, p.server, p.http_status, p.product, p.version, p.http_location,
         p.tls_cn, p.tls_names, p.cert_issuer, p.cert_expiry, p.self_signed, p.favicon,
         CASE WHEN p.tls_cn <> '' OR p.cert_issuer <> '' THEN 'https' ELSE 'http' END AS scheme
  FROM ports p
  -- 判据必须是"有 HTTP/S 应用层响应"，不能是"有证书"。
  -- 只有证书的端口是**服务**不是**站点**：实测本机 3389 的 RDP 也会完成 TLS 握手并
  -- 带回一张 CN=机器名 的自签证书，按证书判定的话它会被算成一个 https 站点。
  WHERE p.state = 'open' AND p.proto = 'tcp'
    AND (p.http_status > 0 OR p.title <> '' OR p.server <> '')
  GROUP BY p.ip, p.port
)
`

// 为什么用 GROUP BY + MAX 而不是 ROW_NUMBER() 窗口函数：
//
// 窗口函数会把**整张表**物化一遍再编号，成本跟端口表规模严格线性——
// 实测 10 万行端口（5 万站点）时首页 410ms、统计 1.45s，列表页刷新一次要等半秒。
// SQLite 对"只有一个 max() 聚合"的查询有明确语义保证：其余裸列取**产生该最大值
// 的那一行**，正好就是"同一 ip:port 以最后观测到的那次为准"。改成聚合后同一个
// 查询降到 40ms 量级（见 TestListSitesScales）。
//
// 代价：first_seen 也取自那一行，而不是所有重复行里最早的一次。重复行本身极少
// （唯一键是 node_key+ip+port，只有同一台机器被流量与扫描器以不同 node_key 写入时
// 才会出现两行），而两行的 first_seen 通常只差几秒。

// siteWhere 构造筛选条件。列名带 d. 前缀，必须配合 siteBase + 别名 d 使用。
func siteWhere(f SiteFilter) (string, []any) {
	var conds []string
	var args []any

	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		if cond, kwArgs := likeAny([]string{
			"d.ip", "d.title", "d.server", "d.product", "d.tls_cn", "d.http_location",
			"m.name", "m.department", "d.cert_issuer",
		}, kw); cond != "" {
			conds = append(conds, cond)
			args = append(args, kwArgs...)
		}
	}
	if f.Port > 0 {
		conds = append(conds, "d.port = ?")
		args = append(args, f.Port)
	}
	switch strings.ToLower(strings.TrimSpace(f.Scheme)) {
	case "http", "https":
		conds = append(conds, "d.scheme = ?")
		args = append(args, strings.ToLower(f.Scheme))
	}
	if f.Tag != "" {
		// 标签存成 JSON 数组文本，用带引号的 LIKE 匹配避免 "oa" 命中 "oax"。
		conds = append(conds, "m.tags LIKE ?")
		args = append(args, "%\""+escapeLike(f.Tag)+"\"%")
	}
	if f.OnlySelfSigned {
		conds = append(conds, "d.self_signed <> 0")
	}
	if f.OnlyExpiring {
		// cert_expiry 是 YYYY-MM-DD 定长文本，字符串比较就是日期比较。
		conds = append(conds, "d.cert_expiry <> '' AND d.cert_expiry >= ? AND d.cert_expiry <= ?")
		now := time.Now()
		args = append(args, now.Format("2006-01-02"), now.AddDate(0, 0, 30).Format("2006-01-02"))
	}
	if f.OnlyExpired {
		conds = append(conds, "d.cert_expiry <> '' AND d.cert_expiry < ?")
		args = append(args, time.Now().Format("2006-01-02"))
	}
	if f.OnlyUntagged {
		conds = append(conds, "(m.site_key IS NULL OR m.tags IN ('', '[]'))")
	}
	if f.OnlineOnly && !f.OnlineAfter.IsZero() {
		conds = append(conds, "d.last_seen >= ?")
		args = append(args, f.OnlineAfter)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// siteFrom 拼出完整的 FROM 子句（含两个 LEFT JOIN）。
const siteFrom = ` FROM site d
  LEFT JOIN assets a ON a.node_key = d.node_key AND a.node_key <> ''
  LEFT JOIN site_meta m ON m.site_key = d.scheme || '://' || d.ip || ':' || d.port`

const siteSelect = `SELECT d.ip, d.port, d.proto, d.node_key, d.scheme,
	d.title, d.server, d.http_status, d.product, d.version, d.http_location,
	d.tls_cn, d.tls_names, d.cert_issuer, d.cert_expiry, d.self_signed, d.favicon,
	d.first_seen, d.last_seen,
	COALESCE(a.hostname, ''), COALESCE(a.status, ''),
	COALESCE(m.name, ''), COALESCE(m.department, ''), COALESCE(m.tags, ''), COALESCE(m.note, '')`

// ListSites 分页查询站点（limit<=0 且 offset<=0 表示不限量）。
func (s *Store) ListSites(f SiteFilter, limit, offset int) ([]model.Site, error) {
	where, args := siteWhere(f)
	q := siteBase + siteSelect + siteFrom + where + ` ORDER BY d.ip, d.port`
	q, args = applyPage(q, args, limit, offset)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Site
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *site)
	}
	return out, rows.Err()
}

// scanSite 把一行站点视图读成 model.Site。
//
// 列表、详情、变更三处共用：列顺序写在 siteSelect 一处，扫描顺序写在 scanSite 一处，
// 加列时只需要改这两个地方——分开写必然出现"列表有、详情没有"的错位。
func scanSite(row rowScanner) (*model.Site, error) {
	var (
		site       model.Site
		tlsNames   string
		certExp    string
		selfSigned int
		assetStat  string
		tags       string
	)
	// 时间列按字符串读、自己解析，不交给驱动做 DATETIME → time.Time 的转换：
	// 经过 CTE 的 MAX() 聚合之后，列的类型亲和性丢了，驱动会把值当成普通 TEXT，
	// Scan 到 time.Time 直接报 "unsupported Scan"。
	var firstSeen, lastSeen string
	if err := row.Scan(&site.IP, &site.Port, &site.Proto, &site.NodeKey, &site.Scheme,
		&site.Title, &site.Server, &site.Status, &site.Product, &site.Version, &site.Location,
		&site.TLSCN, &tlsNames, &site.CertIssuer, &certExp, &selfSigned, &site.Favicon,
		&firstSeen, &lastSeen,
		&site.Hostname, &assetStat,
		&site.Name, &site.Department, &tags, &site.Note); err != nil {
		return nil, err
	}
	site.FirstSeen = scanTime(firstSeen)
	site.LastSeen = scanTime(lastSeen)
	site.Key = site.Scheme + "://" + site.IP + ":" + strconv.Itoa(site.Port)
	site.SelfSigned = selfSigned != 0
	site.CertExpiry = certExp
	site.CertDaysLeft = certDaysLeft(certExp, time.Now())
	if tlsNames != "" && tlsNames != "[]" {
		fromJSON(tlsNames, &site.TLSNames)
	}
	if tags != "" && tags != "[]" {
		fromJSON(tags, &site.Tags)
	}
	site.Risk = siteRisks(&site)
	// 在线判据与端口 stale 同一口径：last_seen 在 PortStaleAfter 之内。
	site.Online = time.Since(site.LastSeen) < PortStaleAfter
	return &site, nil
}

// CountSites 站点总数（与 ListSites 同一套筛选）。
//
// 无筛选条件时结果会短时缓存（见 siteCountCache）。带筛选条件时不缓存：
// 条件组合太多，命中率低而失效逻辑复杂，收益抵不上出错的机会。
func (s *Store) CountSites(f SiteFilter) (int, error) {
	where, args := siteWhere(f)
	if where != "" {
		var n int
		err := s.db.QueryRow(siteBase+`SELECT COUNT(*)`+siteFrom+where, args...).Scan(&n)
		return n, err
	}

	s.siteCount.mu.Lock()
	if s.siteCount.valid && time.Since(s.siteCount.at) < siteCountTTL {
		n := s.siteCount.n
		s.siteCount.mu.Unlock()
		return n, nil
	}
	s.siteCount.mu.Unlock()

	var n int
	if err := s.db.QueryRow(siteBase + `SELECT COUNT(*)` + siteFrom).Scan(&n); err != nil {
		return 0, err
	}

	s.siteCount.mu.Lock()
	s.siteCount.at, s.siteCount.n, s.siteCount.valid = time.Now(), n, true
	s.siteCount.mu.Unlock()
	return n, nil
}

// invalidateSiteCount 让站点总数缓存立刻失效。
//
// 挂在**每一条会改 ports 的写路径**上（单条/批量 upsert、标记 stale、按 node_key 删除），
// 而不是只靠 TTL：靠 TTL 的话，扫描器刚写入 200 个新站点、用户刷新页面
// 仍会看到旧总数，然后去查"为什么站点没增加"——这种不一致比慢难解释得多。
//
// 漏挂一处的症状很隐蔽：只有那条写路径会看到过期总数。所以每次给 ports
// 加写入口时都要回来加一行，TestSiteCountCacheInvalidatesOnWrite 会盯着。
func (s *Store) invalidateSiteCount() {
	s.siteCount.mu.Lock()
	s.siteCount.valid = false
	s.siteCount.mu.Unlock()
}

// scanTime 解析从库里读出的时间文本（聚合列拿到的是原始 TEXT）。
func scanTime(s string) time.Time {
	if t, ok := parseStoredTime(s); ok {
		return t
	}
	return time.Time{}
}

// certDaysLeft 证书剩余天数。-1 表示没有证书情报（与"0 天后过期"必须能区分）。
//
// 按**本地日历日**算，不按 24 小时整除。到期日是"这一天结束"，不是某个时刻；
// 而 time.Truncate(24h) 取的是 UTC 零点（UTC+8 下即本地 08:00），
// 于是本地时间过了 08:00 之后，所有剩余天数都少 1：
//
//	expiry=明天 → 算出 0（应为 1）     expiry=31 天后 → 算出 30 → 误标"即将到期"
//	expiry=昨天 → 算出 -1 → 与"没有证书情报"撞值 → 过期证书被漏报
//
// 最后一条最要紧：report 与 CSV 导出都把 -1 当作"无情报"处理，
// 结果刚过期的证书在报表里既不进"已过期"、也不显示天数。
//
// 除以 24 之后取 Round 而不是直接截断：有夏令时的时区里，切换日只有 23 或 25 小时，
// 截断会把那一天算错一格。
func certDaysLeft(expiry string, now time.Time) int {
	if expiry == "" {
		return -1
	}
	loc := now.Location()
	t, err := time.ParseInLocation("2006-01-02", expiry, loc)
	if err != nil {
		return -1
	}
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, loc)
	return int(math.Round(t.Sub(today).Hours() / 24))
}

// siteRisks 推导风险标签。
//
// 只做提示，不做定性——与全站"只打标签"的口径一致。这里刻意不用"高危/中危"，
// 因为"自签证书"在政务内网是常态而不是缺陷，写成告警会立刻被所有人忽略。
//
// 有没有证书情报，用 CertExpiry 判，**不用 CertDaysLeft == -1**：
// -1 同时是"昨天到期"的合法答案，拿它当哨兵会把刚过期的证书整个漏掉
// （原来写 `< -1` 把它绕过去，代价是过期第一天不报警）。
func siteRisks(site *model.Site) []string {
	var risk []string
	switch {
	case site.CertExpiry == "":
		// 没有证书情报，不参与证书风险评估
	case site.CertDaysLeft < 0:
		risk = append(risk, "cert_expired")
	case site.CertDaysLeft <= 30:
		risk = append(risk, "cert_expiring")
	}
	if site.SelfSigned {
		risk = append(risk, "self_signed")
	}
	if site.Status > 0 && site.Title == "" {
		risk = append(risk, "untitled")
	}
	if site.Scheme == "http" {
		risk = append(risk, "plaintext")
	}
	return risk
}

// SiteStats 站点概览统计。
func (s *Store) SiteStats(f SiteFilter) (*model.SiteStats, error) {
	where, args := siteWhere(f)
	q := siteBase + `SELECT COUNT(*),
	  COALESCE(SUM(CASE WHEN d.last_seen >= ? THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN d.http_status > 0 AND d.title = '' THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN d.self_signed <> 0 THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN d.cert_expiry <> '' AND d.cert_expiry >= ? AND d.cert_expiry <= ? THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN d.cert_expiry <> '' AND d.cert_expiry < ? THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN m.tags NOT IN ('', '[]') THEN 1 ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN d.scheme = 'https' THEN 1 ELSE 0 END), 0)
	` + siteFrom + where

	now := time.Now()
	onlineAfter := now.Add(-PortStaleAfter)
	st := &model.SiteStats{}
	var https int
	// 参数顺序必须与占位符出现顺序一致：统计子句里的 4 个问号在前，
	// 筛选条件的在 where 里排后面。
	statArgs := append([]any{onlineAfter,
		now.Format("2006-01-02"), now.AddDate(0, 0, 30).Format("2006-01-02"),
		now.Format("2006-01-02")}, args...)
	if err := s.db.QueryRow(q, statArgs...).Scan(&st.Total, &st.Online, &st.Untitled, &st.SelfSigned,
		&st.Expiring, &st.Expired, &st.Tagged, &https); err != nil {
		return nil, err
	}
	st.ByScheme = map[string]int{"https": https, "http": st.Total - https}
	if err := s.fillSiteBreakdown(st, where, args); err != nil {
		return st, err
	}
	return st, nil
}

// fillSiteBreakdown 填端口与产品分布。
func (s *Store) fillSiteBreakdown(st *model.SiteStats, where string, args []any) error {
	st.ByPort = map[string]int{}
	st.ByProduct = map[string]int{}
	q := siteBase + `SELECT d.port, COUNT(*)` + siteFrom + where +
		` GROUP BY d.port ORDER BY COUNT(*) DESC, d.port LIMIT 10`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p, n int
		if err := rows.Scan(&p, &n); err != nil {
			rows.Close()
			return err
		}
		st.ByPort[strconv.Itoa(p)] = n
	}
	rows.Close()

	q = siteBase + `SELECT COALESCE(NULLIF(d.product, ''), '未识别'), COUNT(*)` + siteFrom + where +
		` GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 10`
	rows, err = s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return err
		}
		st.ByProduct[name] = n
	}
	return rows.Err()
}

// SiteChange 站点变更项（新增 / 不再活动）。
type SiteChange struct {
	Key       string    `json:"key"`
	Scheme    string    `json:"scheme"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Title     string    `json:"title,omitempty"`
	Product   string    `json:"product,omitempty"`
	Server    string    `json:"server,omitempty"`
	TLSCN     string    `json:"tls_cn,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// SiteChanges 窗口内新增 / 不再活动的站点。
//
// 判据与端口变更视图一致（changes.go）：新增看 first_seen，消失看 last_seen
// 并且 first_seen 也早于窗口起点——否则"窗口内新建又消失"的会被两边都算一次。
func (s *Store) SiteChanges(since time.Time, limit int) (added, gone []SiteChange, err error) {
	if limit <= 0 {
		limit = 200
	}
	base := siteBase + siteSelect + siteFrom
	scan := func(q string, args ...any) ([]SiteChange, error) {
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []SiteChange
		for rows.Next() {
			var (
				c        SiteChange
				proto    string
				nodeKey  string
				status   int
				version  string
				location string
				tlsNames string
				issuer   string
				expiry   string
				selfSig  int
				favicon  string
				first    string
				last     string
				hostname string
				assetSt  string
				name     string
				dept     string
				tags     string
				note     string
			)
			if err := rows.Scan(&c.IP, &c.Port, &proto, &nodeKey, &c.Scheme,
				&c.Title, &c.Server, &status, &c.Product, &version, &location,
				&c.TLSCN, &tlsNames, &issuer, &expiry, &selfSig, &favicon,
				&first, &last, &hostname, &assetSt, &name, &dept, &tags, &note); err != nil {
				return nil, err
			}
			c.Key = c.Scheme + "://" + c.IP + ":" + strconv.Itoa(c.Port)
			// 统一输出 UTC：接口层其它地方（端口列表、站点列表）都按 UTC 出，
			// 这里跟着带本地偏移的话，同一页面上会出现两种时间表示。
			c.FirstSeen, c.LastSeen = scanTime(first).UTC(), scanTime(last).UTC()
			out = append(out, c)
		}
		return out, rows.Err()
	}

	added, err = scan(base+` WHERE d.first_seen >= ? ORDER BY d.first_seen DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, nil, err
	}
	gone, err = scan(base+` WHERE d.last_seen < ? AND d.first_seen < ? ORDER BY d.last_seen DESC LIMIT ?`,
		since, since, limit)
	if err != nil {
		return nil, nil, err
	}
	return added, gone, nil
}

// GetSite 按 key（scheme://ip:port）取单个站点。找不到返回 (nil, nil)。
//
// 直接按 ip+port+scheme 查，不走 ListSites：一个 /16 网段的 80 端口能有几千个站点，
// 为了取一行而把整个 80 端口的列表读进内存是不可接受的（详情页会被反复打开）。
func (s *Store) GetSite(key string) (*model.Site, error) {
	scheme, ip, port, ok := parseSiteKey(key)
	if !ok {
		return nil, fmt.Errorf("站点标识格式错误: %q（应为 scheme://ip:port）", key)
	}
	q := siteBase + siteSelect + siteFrom + ` WHERE d.ip = ? AND d.port = ? AND d.scheme = ?`
	row := s.db.QueryRow(q, ip, port, scheme)
	site, err := scanSite(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return site, nil
}

// parseSiteKey 解析 scheme://ip:port。IPv6 不在支持范围（内网测绘场景里基本不存在）。
func parseSiteKey(key string) (scheme, ip string, port int, ok bool) {
	i := strings.Index(key, "://")
	if i <= 0 {
		return "", "", 0, false
	}
	scheme = strings.ToLower(key[:i])
	rest := key[i+3:]
	j := strings.LastIndex(rest, ":")
	if j <= 0 {
		return "", "", 0, false
	}
	ip = rest[:j]
	p, err := strconv.Atoi(rest[j+1:])
	if err != nil || p <= 0 || p > 65535 {
		return "", "", 0, false
	}
	return scheme, ip, p, true
}

// UpsertSiteMeta 写入人工标注（系统名 / 归属单位 / 标签 / 备注）。
func (s *Store) UpsertSiteMeta(m *model.SiteMeta) error {
	if m.SiteKey == "" {
		return fmt.Errorf("站点标识不能为空")
	}
	if m.Tags == nil {
		m.Tags = []string{}
	}
	m.UpdatedAt = time.Now()
	_, err := s.db.Exec(`INSERT INTO site_meta(site_key, name, department, tags, note, updated_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(site_key) DO UPDATE SET name=excluded.name,
			department=excluded.department, tags=excluded.tags,
			note=excluded.note, updated_at=excluded.updated_at`,
		m.SiteKey, m.Name, m.Department, toJSON(m.Tags), m.Note, m.UpdatedAt)
	return err
}

// DeleteSiteMeta 清除人工标注（回到"没人管过"的状态）。
func (s *Store) DeleteSiteMeta(siteKey string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM site_meta WHERE site_key = ?`, siteKey)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListSiteTags 全部已使用的标签及站点数（标签筛选下拉用）。
func (s *Store) ListSiteTags() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT tags FROM site_meta WHERE tags NOT IN ('', '[]')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var tags []string
		fromJSON(raw, &tags)
		for _, t := range tags {
			out[t]++
		}
	}
	return out, rows.Err()
}

// PruneOrphanSiteMeta 清掉已经不对应任何站点的标注。
//
// 站点是派生视图，端口被清掉（机器离线超期、模板重扫）之后 site_meta 会留下孤儿行。
// 不清理的话标签下拉里会慢慢堆满"点进去什么都没有"的标签。
func (s *Store) PruneOrphanSiteMeta() (int64, error) {
	res, err := s.db.Exec(siteBase + `
	DELETE FROM site_meta WHERE site_key NOT IN (
	  SELECT scheme || '://' || ip || ':' || port FROM site)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
