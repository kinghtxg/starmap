// Package ti 威胁情报（Threat Intelligence）对接。
//
// 解决的问题：拓扑把"国外主机 / 疑似隧道主机 / 中高风险节点"标红外置之后，
// 下一步必然要问"这台到底有没有问题"。这一步不该逼用户去别的平台手工复制 IP——
// 标红的地方就要能直接查情报。
//
// 设计取向（安全产品里这几条比功能重要）：
//  1. **只查公网地址**。把 10.x / 192.168.x 发给第三方情报平台等于自曝内网结构，
//     这是数据外泄而不是查询。内网地址一律拒绝，返回明确原因。
//  2. **手动优先**。默认只有用户点了"查询"才发请求；不自动把整图 IP 批量外发。
//  3. **接口与厂商解耦**。不绑定任何一家：给一个 HTTP 端点 + 字段映射，
//     兼容通用扁平格式与 VirusTotal v3 风格响应。
//  4. **失败要说清楚**。超时、401、非 JSON 都要能区分——"查不到"和"没配置"
//     是两种完全不同的状态，混成一句"查询失败"会让运维白查半天。
package ti

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"starmap/internal/model"
)

// Verdict 情报结论。值定义在 model（本地库、API、回源三方共用一套语义），
// 这里只做别名，避免两处常量各写一份字符串、改一处忘一处。
const (
	VerdictMalicious  = model.VerdictMalicious
	VerdictSuspicious = model.VerdictSuspicious
	VerdictClean      = model.VerdictClean
	VerdictUnknown    = model.VerdictUnknown
)

// Result 一条情报结果。
type Result struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`   // 0-100，越高越危险
	Verdict   string    `json:"verdict"` // malicious|suspicious|clean|unknown
	Tags      []string  `json:"tags,omitempty"`
	Source    string    `json:"source,omitempty"`
	Link      string    `json:"link,omitempty"`
	Cached    bool      `json:"cached"`
	QueriedAt time.Time `json:"queried_at"`
}

// Config 情报接口配置（来自 SystemConfig）。
type Config struct {
	Enabled      bool
	Endpoint     string // 支持 {ip} 占位；不含占位时自动追加 ?ip=
	APIKey       string
	TimeoutMS    int
	CacheSeconds int
}

// ErrDisabled 未启用情报接口。
var ErrDisabled = errors.New("未配置威胁情报接口")

// ErrPrivateIP 内网地址不允许外发查询。
var ErrPrivateIP = errors.New("内网地址不查询外部情报（避免泄露内网结构）")

// ErrRateLimited 请求过于频繁。
var ErrRateLimited = errors.New("查询过于频繁，请稍后再试")

// Client 情报客户端：带 TTL 缓存与单飞合并。
//
// 单飞很重要：拓扑详情面板和后台批量检查可能同时查同一个 IP，
// 没有合并就会把同一条请求发好几遍，既有速率风险也会被对方限流。
type Client struct {
	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]*call
	http     *http.Client
	last     time.Time
	minGap   time.Duration
	cfg      Config
}

type cacheEntry struct {
	res Result
	at  time.Time
}

type call struct {
	done chan struct{}
	res  Result
	err  error
}

// cacheCap 缓存条数上限。情报结果是小对象，但节点会无限增长，必须封顶。
const cacheCap = 4096

// minGap 两次外发查询的最小间隔：情报平台普遍按秒限流，
// 用户连点详情面板很容易打出连续请求。
const minGap = 300 * time.Millisecond

// New 创建客户端（config 允许为未启用状态，此时 Lookup 返回 ErrDisabled）。
func New(cfg Config) *Client {
	to := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if to <= 0 {
		to = 5 * time.Second
	}
	if cfg.CacheSeconds <= 0 {
		cfg.CacheSeconds = 3600
	}
	tr := &http.Transport{
		// 情报接口常是自建内网服务，证书可能是自签的；不校验证书会引入中间人风险，
		// 所以这里保持默认校验，只把超时收紧。自签场景请把 CA 装进系统信任库。
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		cache:    map[string]cacheEntry{},
		inflight: map[string]*call{},
		http:     &http.Client{Timeout: to, Transport: tr},
		minGap:   minGap,
		cfg:      cfg,
	}
}

// Config 返回当前配置（供 /api/config 判断是否已配置，不含密钥明文）。
func (c *Client) Config() Config { return c.cfg }

// Lookup 查询 IP 情报。force=true 时忽略缓存。
func (c *Client) Lookup(ctx context.Context, ip string, force bool) (Result, error) {
	if !c.cfg.Enabled || strings.TrimSpace(c.cfg.Endpoint) == "" {
		return Result{}, ErrDisabled
	}
	ip = strings.TrimSpace(ip)
	if i := strings.IndexByte(ip, '/'); i >= 0 { // 外部聚合节点存的是 /24
		ip = ip[:i]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Result{}, fmt.Errorf("非法 IP：%s", ip)
	}
	// 只查公网地址：这不是"性能优化"，是数据边界。
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsMulticast() || parsed.IsUnspecified() {
		return Result{}, ErrPrivateIP
	}

	c.mu.Lock()
	if e, ok := c.cache[ip]; ok && !force {
		ttl := time.Duration(c.cfg.CacheSeconds) * time.Second
		if time.Since(e.at) < ttl {
			res := e.res
			res.Cached = true
			c.mu.Unlock()
			return res, nil
		}
	}
	// 单飞：同一个 IP 已有请求在途，直接等它的结果
	if cl, ok := c.inflight[ip]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.res, cl.err
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	// 限速
	if wait := c.minGap - time.Since(c.last); wait > 0 {
		c.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
		c.mu.Lock()
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[ip] = cl
	c.last = time.Now()
	c.mu.Unlock()

	res, err := c.fetch(ctx, ip)

	c.mu.Lock()
	delete(c.inflight, ip)
	cl.res, cl.err = res, err
	close(cl.done)
	if err == nil {
		if len(c.cache) >= cacheCap {
			c.evictLocked()
		}
		res.Cached = false
		c.cache[ip] = cacheEntry{res: res, at: time.Now()}
	}
	c.mu.Unlock()
	return res, err
}

// evictLocked 先清过期，再不行就整体丢弃（情报随时可重查，不值得为它做 LRU）。
func (c *Client) evictLocked() {
	ttl := time.Duration(c.cfg.CacheSeconds) * time.Second
	now := time.Now()
	for k, e := range c.cache {
		if now.Sub(e.at) >= ttl {
			delete(c.cache, k)
		}
	}
	if len(c.cache) >= cacheCap/2 {
		c.cache = map[string]cacheEntry{}
	}
}

// fetch 真正的 HTTP 调用与响应解析。
func (c *Client) fetch(ctx context.Context, ip string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.buildURL(ip), nil)
	if err != nil {
		return Result{}, fmt.Errorf("构造请求失败：%w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("情报接口不可达：%w", err)
	}
	defer resp.Body.Close()
	// 防止对端返回巨大响应把内存打满（情报接口也可能是被攻陷的内网服务）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, fmt.Errorf("读取响应失败：%w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{}, fmt.Errorf("情报接口拒绝访问（HTTP %d），检查 API Key", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{}, ErrRateLimited
	case resp.StatusCode >= 400:
		return Result{}, fmt.Errorf("情报接口返回 HTTP %d", resp.StatusCode)
	}
	res, err := parse(body)
	if err != nil {
		return Result{}, err
	}
	res.IP = ip
	res.QueriedAt = time.Now().UTC()
	if res.Source == "" {
		if u, e := url.Parse(c.cfg.Endpoint); e == nil {
			res.Source = u.Host
		}
	}
	return res, nil
}

// buildURL 拼请求地址：优先替换 {ip} 占位；否则按需追加 ?ip=。
func (c *Client) buildURL(ip string) string {
	ep := strings.TrimSpace(c.cfg.Endpoint)
	if strings.Contains(ep, "{ip}") {
		return strings.ReplaceAll(ep, "{ip}", url.PathEscape(ip))
	}
	u, err := url.Parse(ep)
	if err != nil {
		return ep
	}
	q := u.Query()
	if q.Get("ip") == "" && q.Get("query") == "" {
		q.Set("ip", ip)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// rawResp 兼容两种常见响应形态：
//   - 扁平：{"score":87,"verdict":"malicious","tags":[...],"source":"...","link":"..."}
//   - VirusTotal v3：{"data":{"attributes":{"last_analysis_stats":{...},"reputation":-20}}}
type rawResp struct {
	Score   *int     `json:"score"`
	Verdict string   `json:"verdict"`
	Tags    []string `json:"tags"`
	Source  string   `json:"source"`
	Link    string   `json:"link"`

	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			Reputation int      `json:"reputation"`
			Tags       []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

// parse 解析响应体并归一化成分数与结论。
func parse(body []byte) (Result, error) {
	var raw rawResp
	if err := json.Unmarshal(body, &raw); err != nil {
		// 有些平台对"无记录"直接返回空体或纯文本
		if len(strings.TrimSpace(string(body))) == 0 {
			return Result{Verdict: VerdictUnknown}, nil
		}
		return Result{}, fmt.Errorf("情报响应不是合法 JSON：%w", err)
	}
	res := Result{Tags: raw.Tags, Source: raw.Source, Link: raw.Link, Verdict: raw.Verdict}
	if raw.Score != nil {
		res.Score = clampScore(*raw.Score)
	} else if st := raw.Data.Attributes.LastAnalysisStats; st.Malicious+st.Suspicious+st.Harmless+st.Undetected > 0 {
		// VT 风格：按"有害占比"折算 0-100
		total := st.Malicious + st.Suspicious + st.Harmless + st.Undetected
		res.Score = clampScore((st.Malicious*100 + st.Suspicious*50) / total)
		res.Tags = append(res.Tags, raw.Data.Attributes.Tags...)
	}
	if res.Verdict == "" {
		res.Verdict = verdictOf(res.Score)
	}
	if len(res.Tags) > 20 { // 对端可控字段，别无限往界面塞
		res.Tags = res.Tags[:20]
	}
	for i, t := range res.Tags {
		if len(t) > 40 {
			res.Tags[i] = t[:40]
		}
	}
	return res, nil
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func verdictOf(score int) string {
	switch {
	case score >= 70:
		return VerdictMalicious
	case score >= 40:
		return VerdictSuspicious
	case score > 0:
		return VerdictClean
	default:
		return VerdictUnknown
	}
}

// Summary 生成一句话结论（界面上直接展示，避免前端各自拼）。
// Record 把回源结果转成本地情报记录（写入本地库，下次直接命中）。
//
// UpdatedAt 用查询时间：情报平台没给数据时间时，这就是我们能拿到的最新证据。
// Kind 交给 store 层的规范化去判定，这里不重复解析。
func (r Result) Record(ip, source string) model.IntelRecord {
	at := r.QueriedAt
	if at.IsZero() {
		at = time.Now()
	}
	return model.IntelRecord{
		Indicator:  ip,
		Verdict:    r.Verdict,
		Score:      r.Score,
		Tags:       r.Tags,
		Source:     source,
		UpdatedAt:  at.UTC(),
		ReceivedAt: time.Now().UTC(),
	}
}

func (r Result) Summary() string {
	if r.Verdict == VerdictUnknown && r.Score == 0 {
		return "无情报记录"
	}
	return r.Verdict + " · 风险分 " + strconv.Itoa(r.Score)
}
