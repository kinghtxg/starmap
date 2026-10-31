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
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/model"
	"starmap/internal/ti"
	"starmap/internal/topology"
)

// 自有威胁情报对接（V1.5）。
//
// 两条通路，语义不同，不要混：
//
//	推送（本文件 pushIntel）  情报平台 → StarMap，落本地库。机器到机器，凭令牌。
//	回源（lookupTI）          本地没有时 StarMap → 情报 API，一次一个地址。
//
// 标红只看本地库：出图时批量查一次库，命中毒性判定就把节点标红。
// 回源是"人主动点开某台机器"才发生的动作，不是出图路径上的副作用——
// 否则打开一次拓扑就会把整图地址发给外部系统。

// maxIntelPerPush 单次推送的记录上限。
// 超过这个量级应该由推送方分批：一次几十万条会在单个连接上把库锁住几分钟，
// 期间事件写入全部排队（库是单连接），表现为"拓扑卡住不刷新"。
const maxIntelPerPush = 20000

// intelPushRecord 推送记录。字段名留了别名：
// 情报平台的数据模型各不相同，我们按"最可能出现的几种命名"接收，
// 少的字段用默认值补，绝不因为一个字段名不同就整批拒收。
type intelPushRecord struct {
	Indicator  string          `json:"indicator"`
	IP         string          `json:"ip"`
	Value      string          `json:"value"`
	IOC        string          `json:"ioc"`
	Host       string          `json:"host"`
	Verdict    string          `json:"verdict"`
	Level      string          `json:"level"`
	Status     string          `json:"status"`
	Score      int             `json:"score"`
	Confidence int             `json:"confidence"`
	Tags       []string        `json:"tags"`
	Tag        string          `json:"tag"`
	UpdatedAt  string          `json:"updated_at"`
	Updated    string          `json:"updated"`
	Version    int64           `json:"version"`
	Rev        int64           `json:"rev"`
	Source     string          `json:"source"`
	Raw        json.RawMessage `json:"raw"`
}

func (r intelPushRecord) indicator() string {
	for _, v := range []string{r.Indicator, r.IP, r.Value, r.IOC, r.Host} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (r intelPushRecord) verdict(def string) string {
	for _, v := range []string{r.Verdict, r.Level, r.Status} {
		if v = strings.TrimSpace(v); v != "" {
			return normalizeVerdict(v)
		}
	}
	return def
}

func (r intelPushRecord) score() int {
	if r.Score != 0 {
		return r.Score
	}
	return r.Confidence
}

func (r intelPushRecord) tags() []string {
	out := r.Tags
	if strings.TrimSpace(r.Tag) != "" {
		out = append(out, strings.FieldsFunc(r.Tag, func(c rune) bool {
			return c == '|' || c == ',' || c == ';'
		})...)
	}
	return out
}

func (r intelPushRecord) version() int64 {
	if r.Version != 0 {
		return r.Version
	}
	return r.Rev
}

func (r intelPushRecord) updatedAt() time.Time {
	for _, s := range []string{r.UpdatedAt, r.Updated} {
		if t, ok := parseIntelTime(s); ok {
			return t
		}
	}
	return time.Time{}
}

// normalizeVerdict 把各家五花八门的判定归一到四个值。
// 归一化是必要的：下游标红只认 malicious/suspicious，认不出 "blacklist" 就等于没命中。
func normalizeVerdict(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "malicious", "bad", "black", "blacklist", "c2", "botnet", "恶", "恶意", "黑":
		return "malicious"
	case "suspicious", "warn", "warning", "gray", "grey", "可疑", "灰":
		return "suspicious"
	case "clean", "good", "white", "whitelist", "benign", "safe", "正常", "白":
		return "clean"
	}
	return "unknown"
}

// parseIntelTime 兼容三种常见时间写法：RFC3339、数据库导出的 "2006-01-02 15:04:05"、Unix 秒。
func parseIntelTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05", "2006-01-02T15:04:05",
		"2006-01-02 15:04", "2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		if sec > 1e12 { // 毫秒
			return time.UnixMilli(sec).UTC(), true
		}
		return time.Unix(sec, 0).UTC(), true
	}
	return time.Time{}, false
}

// pushIntel 接收情报推送（POST /api/intel/push）。
//
// 鉴权：必须配置 intel_push_token 且请求携带令牌。
// 不像探针上报那样允许"未配令牌即放行"——探针写的是观测数据，最多让拓扑多几台机器；
// 情报写的是**结论**，一个匿名入口就能把任意地址标黑（诬告）或标白（洗白）。
func (s *Server) pushIntel(c *gin.Context) {
	want := s.cfg().IntelPushToken
	if want == "" {
		fail(c, http.StatusForbidden,
			"未配置推送令牌（系统配置 → 威胁情报 → 推送令牌），拒绝接收情报推送")
		return
	}
	got := c.GetHeader("X-Intel-Token")
	if got == "" {
		if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			got = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if got == "" {
		got = c.Query("token")
	}
	if !secureEqual(got, want) {
		fail(c, http.StatusUnauthorized, "推送令牌校验失败")
		return
	}

	body, err := readBody(c)
	if err != nil {
		return
	}

	recs, src, err := parseIntelPayload(body, c.Query("verdict"))
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if len(recs) == 0 {
		fail(c, http.StatusBadRequest, "没有解析到任何情报记录（检查 records/indicators 字段）")
		return
	}
	if len(recs) > maxIntelPerPush {
		fail(c, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("单次最多 %d 条，本次 %d 条，请分批推送", maxIntelPerPush, len(recs)))
		return
	}
	// 来源：记录里没写就用整批声明的 source；整批也没声明就留空。
	// 不编一个 "push" 出来——那会被当成某个真实情报源，统计里再也分不清谁给的。
	// 空来源在 store 层不会覆盖库里已知的来源。
	for i := range recs {
		if recs[i].Source == "" && src != "" {
			recs[i].Source = src
		}
	}

	stat, err := s.d.Store.UpsertIntelBatch(recs)
	if err != nil {
		internalError(c, err, "写入情报失败")
		return
	}
	if src == "" {
		src = "(未标注)"
	}
	s.d.Reviewer.Audit(s.actor(c), "intel_push", fmt.Sprintf("source=%s", src),
		fmt.Sprintf("收到 %d 条：新增 %d / 覆盖 %d / 未变 %d / 过期拒收 %d / 同版冲突 %d / 非法 %d",
			stat.Received, stat.Inserted, stat.Updated, stat.Unchanged,
			stat.Stale, stat.Conflict, stat.Invalid))

	resp := gin.H{"source": src, "stat": stat}
	// 有过期拒收必须说出来：推送方看到 200 会以为全部生效了
	if stat.Stale > 0 {
		resp["warning"] = fmt.Sprintf(
			"%d 条比库里的版本旧，已拒绝（不会被覆盖）。请检查推送方的时钟或 version 是否单调递增。",
			stat.Stale)
	}
	// 同版本不同结论：独立说，否则推送方会去检查时钟（而问题在版本号没升）
	if stat.Conflict > 0 {
		resp["conflict_hint"] = fmt.Sprintf(
			"%d 条的 version 与 updated_at 都和库里相同、但结论不同，已拒绝。"+
				"同一个版本必须对应同一个结论：要改变判定请递增 version，否则等于允许无声改写已发布的情报。",
			stat.Conflict)
	}
	if stat.Invalid > 0 {
		resp["invalid_hint"] = "非法记录已跳过（地址格式不合法），其余记录正常入库"
	}
	c.JSON(http.StatusOK, resp)
}

func readBody(c *gin.Context) ([]byte, error) {
	// 体积上限由 bodyLimit 中间件用 MaxBytesReader 兜住（本路由放宽到 64MB），
	// 这里只需要把错误翻译成 413。
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(c, http.StatusRequestEntityTooLarge,
				"情报推送体超过上限（"+strconv.FormatInt(tooLarge.Limit, 10)+" 字节），请分批推送")
			return nil, err
		}
		fail(c, http.StatusBadRequest, "读取请求体失败")
		return nil, err
	}
	return b, nil
}

// parseIntelPayload 解析推送体，JSON 优先，其次纯文本/CSV 的"每行一个指标"。
func parseIntelPayload(body []byte, defVerdict string) ([]model.IntelRecord, string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, "", errors.New("请求体为空")
	}
	def := normalizeVerdict(defVerdict)
	if defVerdict == "" {
		def = "unknown"
	}

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return parseIntelJSON(body, def)
	}
	return parseIntelText(trimmed, def, defVerdict == "")
}

func parseIntelJSON(body []byte, def string) ([]model.IntelRecord, string, error) {
	// 允许直接推数组
	if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		var arr []intelPushRecord
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, "", fmt.Errorf("解析情报数组失败: %v", err)
		}
		return convertIntelRecords(arr, def), "", nil
	}

	var payload struct {
		Source  string `json:"source"`
		Verdict string `json:"verdict"`
		// 四种常见包装字段，取第一个非空的
		Records    []intelPushRecord `json:"records"`
		Indicators []intelPushRecord `json:"indicators"`
		Data       []intelPushRecord `json:"data"`
		Items      []intelPushRecord `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", fmt.Errorf("解析情报 JSON 失败: %v", err)
	}
	if payload.Verdict != "" {
		def = normalizeVerdict(payload.Verdict)
	}
	list := payload.Records
	if len(list) == 0 {
		list = payload.Indicators
	}
	if len(list) == 0 {
		list = payload.Data
	}
	if len(list) == 0 {
		list = payload.Items
	}
	return convertIntelRecords(list, def), payload.Source, nil
}

func convertIntelRecords(list []intelPushRecord, def string) []model.IntelRecord {
	out := make([]model.IntelRecord, 0, len(list))
	for _, r := range list {
		ind := r.indicator()
		if strings.TrimSpace(ind) == "" {
			// 空记录留个占位，让 UpsertIntelBatch 计入 Invalid（总量对得上，便于排查）
			out = append(out, model.IntelRecord{Indicator: ""})
			continue
		}
		raw := ""
		if len(r.Raw) > 0 && len(r.Raw) <= 512 {
			raw = string(r.Raw)
		}
		out = append(out, model.IntelRecord{
			Indicator: ind,
			Verdict:   r.verdict(def),
			Score:     r.score(),
			Tags:      r.tags(),
			Source:    r.Source,
			Version:   r.version(),
			UpdatedAt: r.updatedAt(),
			Raw:       raw,
		})
	}
	return out
}

// parseIntelText 解析纯文本 / CSV：每行 "指标[,判定[,分值[,标签]]]"，支持 # 注释。
func parseIntelText(text string, def string, needVerdict bool) ([]model.IntelRecord, string, error) {
	var out []model.IntelRecord
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 跳过表头
		if strings.EqualFold(line, "ip,verdict") || strings.HasPrefix(strings.ToLower(line), "indicator") {
			continue
		}
		parts := strings.Split(line, ",")
		rec := model.IntelRecord{Indicator: strings.TrimSpace(parts[0]), Verdict: def}
		if len(parts) > 1 {
			if v := normalizeVerdict(parts[1]); v != "unknown" {
				rec.Verdict = v
			}
		}
		if len(parts) > 2 {
			if n, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil {
				rec.Score = n
			}
		}
		if len(parts) > 3 {
			for _, t := range strings.Split(parts[3], "|") {
				if t = strings.TrimSpace(t); t != "" {
					rec.Tags = append(rec.Tags, t)
				}
			}
		}
		if needVerdict && len(parts) == 1 {
			return nil, "", errors.New(
				"纯文本模式只给指标不给判定时，必须用 ?verdict=malicious|suspicious|clean 指定整批判定")
		}
		out = append(out, rec)
	}
	return out, "", nil
}

// intelStats 本地情报库概况（GET /api/intel/stats）。
func (s *Server) intelStats(c *gin.Context) {
	st, err := s.d.Store.IntelStats()
	if err != nil {
		internalError(c, err, "读取情报统计失败")
		return
	}
	cfg := s.cfg()
	st["push_token_set"] = cfg.IntelPushToken != ""
	st["remote_enabled"] = cfg.TIEnabled && cfg.TIEndpoint != ""
	st["retention_days"] = cfg.IntelRetentionDays
	c.JSON(http.StatusOK, st)
}

// listIntel 列出本地情报（GET /api/intel?verdict=&limit=&offset=）。
func (s *Server) listIntel(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	list, total, err := s.d.Store.ListIntel(strings.TrimSpace(c.Query("verdict")), limit, offset)
	if err != nil {
		internalError(c, err, "读取情报列表失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"Records": list, "Total": total})
}

// deleteIntel 人工删除一条情报（纠错用，DELETE /api/intel/:indicator）。
func (s *Server) deleteIntel(c *gin.Context) {
	ind := c.Param("indicator")
	if err := s.d.Store.DeleteIntel(ind); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "intel_delete", ind, "")
	c.Status(http.StatusNoContent)
}

// annotateIntel 给一批节点挂上本地情报结论（出图路径上批量查一次）。
//
// 为什么不放在 buildNodeJSON 里：那会让每个节点各查一次库，几百个节点就是
// 几百次 SQL。这里一次 IN 查询（每 400 个一批）解决。
// 查询失败不影响出图——情报是增强信息，不该让它把整张图拖挂。
func nodeIntelKeys(n *model.Node) []string {
	// 外部聚合节点的 IP 是 "203.0.113.0/24" 这种形式，情报库里既可能是整段，
	// 也可能是段里某个单 IP。两种键都要试，否则"段级情报"永远命不中。
	keys := make([]string, 0, len(n.IPs)+1)
	seen := make(map[string]bool, len(n.IPs)+1)
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		keys = append(keys, v)
	}
	add(primaryNodeIP(n))
	for _, raw := range n.IPs {
		add(raw)
	}
	return keys
}

func (s *Server) annotateIntel(nodes []model.Node) {
	if len(nodes) == 0 || s.d.Store == nil {
		return
	}
	cand := make([]string, 0, len(nodes)*2)
	for i := range nodes {
		cand = append(cand, nodeIntelKeys(&nodes[i])...)
	}
	if len(cand) == 0 {
		return
	}
	m, err := s.d.Store.LookupIntelBatch(cand)
	if err != nil || len(m) == 0 {
		return
	}
	for i := range nodes {
		for _, k := range nodeIntelKeys(&nodes[i]) {
			r, ok := m[k]
			if !ok {
				continue
			}
			nodes[i].IntelVerdict = r.Verdict
			nodes[i].IntelScore = r.Score
			nodes[i].IntelTags = r.Tags
			break
		}
	}
}

// annotateIntelOne 单节点补情报（详情面板用）。
func (s *Server) annotateIntelOne(n *model.Node) {
	if n == nil {
		return
	}
	batch := []model.Node{*n}
	s.annotateIntel(batch)
	n.IntelVerdict, n.IntelScore, n.IntelTags = batch[0].IntelVerdict, batch[0].IntelScore, batch[0].IntelTags
}

// lookupTI 节点情报查询（GET /api/nodes/:id/ti?refresh=1）。
//
// 顺序是"本地优先，缺了再回源"，因为：
//   - 本地库是自有数据，查它不产生任何外发，也不受只查公网的约束；
//   - 回源要花钱/花配额/留外发痕迹，只在真的没有数据时才做。
//
// 只查公网地址：内网地址外发等于自曝结构，ti 包在发起请求前就拒绝。
func (s *Server) lookupTI(c *gin.Context) {
	id := c.Param("id")
	kind, num, cidr := topology.ParseAPINodeID(id)
	var node *model.Node
	switch kind {
	case "node":
		node = s.d.Engine.GetNode(num)
	case "ext":
		node = s.d.Engine.NodeByExternalCIDR(cidr)
	case "subnet":
		fail(c, http.StatusBadRequest, "网段聚合节点没有单一 IP，请展开网段后选择具体主机")
		return
	}
	if node == nil {
		fail(c, http.StatusNotFound, "节点不存在: "+id)
		return
	}
	ip := primaryNodeIP(node)
	if ip == "" {
		fail(c, http.StatusBadRequest, "该节点没有可用于查询的 IP")
		return
	}

	cfg := s.cfg()
	force := c.Query("refresh") == "1"
	remoteReady := cfg.TIEnabled && cfg.TIEndpoint != ""
	now := time.Now().UTC()

	// 1) 本地库
	var local *model.IntelRecord
	if !force {
		for _, k := range nodeIntelKeys(node) {
			if r, err := s.d.Store.LookupIntel(k); err == nil && r != nil {
				local = r
				break
			}
		}
	}
	if local != nil && (local.ExpiresAt == nil || local.ExpiresAt.After(now)) {
		c.JSON(http.StatusOK, gin.H{
			"configured": true, "ok": true, "source": "local",
			"record": local, "summary": intelSummary(ip, local),
		})
		return
	}

	// 2) 回源
	if !remoteReady {
		if local != nil {
			// 有本地数据但已过期，且没配回源：把过期数据照原样给出去，并明说它旧了
			c.JSON(http.StatusOK, gin.H{
				"configured": false, "ok": true, "source": "local", "stale": true,
				"record": local, "summary": intelSummary(ip, local) + "（数据已过有效期）",
				"message": "未配置回源接口，显示的是本地库里的历史结论",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"configured": false, "source": "none",
			"message": "本地情报库没有该地址的记录，且未配置回源接口（系统配置 → 威胁情报）",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(),
		time.Duration(cfg.TITimeoutMS)*time.Millisecond+2*time.Second)
	defer cancel()
	res, err := s.tiClient().Lookup(ctx, ip, force)
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, ti.ErrPrivateIP):
			status = http.StatusBadRequest
		case errors.Is(err, ti.ErrDisabled):
			status = http.StatusServiceUnavailable
		case errors.Is(err, ti.ErrRateLimited):
			status = http.StatusTooManyRequests
		}
		c.JSON(status, gin.H{"configured": true, "ok": false, "message": err.Error()})
		return
	}

	// 3) 回源结果写回本地库，下次直接命中（带有效期，到期后允许再问）
	rec := res.Record(ip, "remote")
	exp := now.Add(time.Duration(cfg.TICacheSeconds) * time.Second)
	rec.ExpiresAt = &exp
	rec.ReceivedAt = now
	if _, uerr := s.d.Store.UpsertIntelBatch([]model.IntelRecord{rec}); uerr != nil {
		// 写回失败不影响这次回答，但要说出来：否则用户会以为"下次还会这么快"
		c.JSON(http.StatusOK, gin.H{
			"configured": true, "ok": true, "source": "remote",
			"record": rec, "summary": intelSummary(ip, &rec),
			"message": "结果已返回，但写回本地库失败：" + uerr.Error(),
		})
		return
	}
	s.d.Reviewer.Audit(s.actor(c), "ti_lookup", ip, intelSummary(ip, &rec))
	c.JSON(http.StatusOK, gin.H{
		"configured": true, "ok": true, "source": "remote",
		"record": rec, "summary": intelSummary(ip, &rec),
	})
}

func intelSummary(ip string, r *model.IntelRecord) string {
	if r == nil {
		return ip + "：本地情报库无记录"
	}
	s := ip + "：" + r.Verdict
	if r.Score > 0 {
		s += fmt.Sprintf("（置信度 %d）", r.Score)
	}
	if len(r.Tags) > 0 {
		s += " · " + strings.Join(r.Tags, "/")
	}
	return s
}
