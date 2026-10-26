package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 服务指纹：把"这个端口开着"升级为"这个端口上跑的是什么"。
//
// 只做端口扫描的资产台账价值有限——运维看到 "10.1.2.3:8080 开放" 无法判断该不该管；
// 看到 "泛微 e-cology" / "海康威视 NVR" / "TLS 证书 CN=oa.xxx.gov.cn，2023-06-01 已过期"
// 才有处置优先级。灯塔之所以好用，很大一部分来自这一层。
//
// 采集四类证据，互为补充：
//  1. HTTP：状态码、Server、页面标题、跳转地址——最直接的产品暴露面；
//  2. TLS：证书 CN / SAN / 签发者 / 到期时间——能把"一串 IP"还原成"哪个业务系统"，
//     内网大量自签与过期证书本身就是风险信号；
//  3. Banner：SSH / FTP / SMTP / MySQL / Redis 等非 HTTP 服务的首包；
//  4. favicon hash：跨 IP、跨域名关联同一套系统的硬指纹。

// FingerprintOptions 一次指纹探测的参数。
type FingerprintOptions struct {
	Timeout      time.Duration // 单次请求超时（默认 3s）
	MaxBody      int64         // 读取响应体上限（默认 64KB，够拿到 <title> 又不至于被大文件拖住）
	FetchFavicon bool          // 是否取 /favicon.ico 算哈希
}

// DefaultFingerprintOptions 默认参数。
func DefaultFingerprintOptions() FingerprintOptions {
	return FingerprintOptions{Timeout: 3 * time.Second, MaxBody: 64 << 10, FetchFavicon: true}
}

func (o FingerprintOptions) normalize() FingerprintOptions {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Timeout > 30*time.Second {
		o.Timeout = 30 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 64 << 10
	}
	if o.MaxBody > 1<<20 {
		o.MaxBody = 1 << 20
	}
	return o
}

// Fingerprint 单端口指纹结果。
type Fingerprint struct {
	Port       int      `json:"port"`
	Service    string   `json:"service,omitempty"`      // 归一化服务名
	Product    string   `json:"product,omitempty"`      // 产品名
	Version    string   `json:"version,omitempty"`      // 版本号
	Title      string   `json:"title,omitempty"`        // 页面标题
	Server     string   `json:"server,omitempty"`       // Server 响应头
	Status     int      `json:"status,omitempty"`       // HTTP 状态码
	Location   string   `json:"location,omitempty"`     // 跳转地址（内网常借此暴露真实域名）
	Banner     string   `json:"banner,omitempty"`       // 非 HTTP 服务的首包
	TLS        bool     `json:"tls,omitempty"`          // 是否 TLS 服务
	TLSCN      string   `json:"tls_cn,omitempty"`       // 证书 CN
	TLSNames   []string `json:"tls_names,omitempty"`    // 证书 SAN（DNS + IP）
	CertIssuer string   `json:"cert_issuer,omitempty"`  // 签发者
	CertExpiry string   `json:"cert_expiry,omitempty"`  // 到期日（YYYY-MM-DD）
	SelfSigned bool     `json:"self_signed,omitempty"`  // 自签证书
	Favicon    string   `json:"favicon_hash,omitempty"` // favicon mmh3
}

// userAgent 用一个普通浏览器 UA：某些国产设备会按 UA 返回不同的登录页，
// 用自定义 UA 会拿到 "不支持的浏览器" 页面，反而识别不出产品。
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"

// bannerProbes 少数服务端不主动发首包，需要发一条**只读**命令才肯说话。
// 只放只读命令（PING / version / srvr），任何写操作都不在探测范围内。
var bannerProbes = map[int]string{
	6379:  "PING\r\n",    // Redis：回 +PONG
	11211: "version\r\n", // memcached：回 VERSION x.y.z
	2181:  "srvr\r\n",    // ZooKeeper：回版本与角色
}

// bannerPorts 值得抓 banner 的端口（其余端口抓了也只是超时等待：一个开放但不说话的
// 端口会白等满一个超时，/24 网段累起来就是几分钟的无谓延迟）。
var bannerPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 110: true, 143: true, 465: true,
	587: true, 993: true, 995: true, 3306: true, 5432: true, 6379: true,
	11211: true, 2181: true, 5900: true, 873: true, 1883: true, 27017: true,
}

// shouldGrabBanner 判断某端口是否值得抓 banner。
// 抽成变量是为了让测试能覆盖这条判断（测试用的是随机端口，不可能命中上面的端口表）。
var shouldGrabBanner = func(port int) bool {
	return bannerPorts[port] || tlsPorts[port]
}

// Fingerprint 对单端口做指纹识别。
// 返回 nil + error 表示该端口没有给出任何可识别的应用层响应（可能是扫描后被关掉了、
// 或者是纯 L4 转发端口），调用方应把它当成"端口开着但无指纹"，不是扫描失败。
func (s *Scanner) Fingerprint(ctx context.Context, ip string, port int, opt FingerprintOptions) (*Fingerprint, error) {
	opt = opt.normalize()
	fp := &Fingerprint{Port: port}

	var (
		res    probeResult
		scheme string
	)

	// TLS 端口先走 https，其它端口先走明文 http。
	schemes := []string{"http", "https"}
	if tlsPorts[port] {
		schemes = []string{"https", "http"}
	}
	for _, sc := range schemes {
		r, ok := s.httpProbe(ctx, ip, port, sc, opt, fp)
		if !ok {
			continue
		}
		// nginx / Go 这类 TLS 服务在收到明文请求时会**返回 400**而不是断开，
		// 若不识别就会把一个 HTTPS 站点误判成"明文 400 页面"，证书情报也一起丢掉。
		if sc == "http" && looksLikePlainOnTLS(r.body) {
			continue
		}
		res, scheme = r, sc
		break
	}
	if res.web {
		fp.Status = res.status
		fp.Server = res.server
		fp.Title = res.title
		if res.location != "" {
			fp.Location = res.location
		}
	}

	// 不是 Web：按需抓 banner（只对可能有服务端首包的端口抓，避免白等超时）。
	if !res.web {
		if shouldGrabBanner(port) || fp.TLS {
			fp.Banner = s.grabBanner(ctx, ip, port, opt.Timeout, fp)
		}
		if fp.Banner == "" && !fp.TLS {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("端口 %d 无可识别的应用层响应", port)
		}
	}

	if res.web && opt.FetchFavicon {
		fp.Favicon = s.fetchFavicon(ctx, ip, port, scheme, opt, fp)
	}

	product, version, service := matchRules(ruleInput{
		header: strings.ToLower(res.header),
		body:   strings.ToLower(res.body),
		banner: strings.ToLower(fp.Banner),
		title:  strings.ToLower(fp.Title),
		port:   port,
	})
	fp.Product, fp.Version = product, version
	if service == "" {
		service = guessService(port, res.web, fp.TLS)
	}
	fp.Service = service
	return fp, nil
}

type probeResult struct {
	body     string
	header   string
	title    string
	server   string
	location string
	status   int
	web      bool
}

// looksLikePlainOnTLS 判断"明文请求打到了 TLS 端口"的典型响应。
// nginx 回 400 + "The plain HTTP request was sent to HTTPS port"，
// Go 的 net/http 回 400 + "Client sent an HTTP request to an HTTPS server"。
// 命中时应继续尝试 https，而不是把 400 当成正常指纹。
func looksLikePlainOnTLS(body string) bool {
	if len(body) > 2048 {
		body = body[:2048]
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "plain http request was sent to https port") ||
		strings.Contains(low, "http request to an https server")
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle 从 HTML 里取标题并做清洗（去标签、解实体、压空白、截断）。
func extractTitle(page string) string {
	m := titleRE.FindStringSubmatch(page)
	if len(m) < 2 {
		return ""
	}
	t := html.UnescapeString(m[1])
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

// httpProbe 对指定 scheme 发一次 GET /，成功（拿到任何一个 HTTP 响应，含 3xx/4xx/5xx）
// 即认为该端口是 Web 服务：401/403 的登录页同样是极有价值的指纹来源。
func (s *Scanner) httpProbe(ctx context.Context, ip string, port int, scheme string, opt FingerprintOptions, fp *Fingerprint) (probeResult, bool) {
	client, closeFn := s.httpClientFor(ip, port, opt, fp)
	defer closeFn()

	url := scheme + "://" + net.JoinHostPort(ip, itoa(port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return probeResult{}, false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBody))

	var hb strings.Builder
	hb.WriteString(resp.Proto)
	hb.WriteString(" ")
	hb.WriteString(resp.Status)
	hb.WriteString("\n")
	_ = resp.Header.Write(&hb)

	return probeResult{
		body:     string(body),
		header:   hb.String(),
		title:    extractTitle(string(body)),
		server:   resp.Header.Get("Server"),
		location: resp.Header.Get("Location"),
		status:   resp.StatusCode,
		web:      true,
	}, true
}

// httpClientFor 构造一次性的 HTTP 客户端：
// 不跟随跳转（跳转地址本身是情报）、不复用连接、跳过证书校验（内网几乎全是自签）。
// 拨号统一走 s.dialTCP，测试时可以注入假连接。
func (s *Scanner) httpClientFor(ip string, port int, opt FingerprintOptions, fp *Fingerprint) (*http.Client, func()) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	tr := &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        tlsCfg,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialTCP(ctx, ip, port, opt.Timeout)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := s.dialTCP(ctx, ip, port, opt.Timeout)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(conn, tlsCfg)
			hctx, cancel := context.WithTimeout(ctx, opt.Timeout)
			defer cancel()
			if err := tc.HandshakeContext(hctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 && fp != nil {
				fp.TLS = true
				applyCertState(fp, &st)
			}
			return tc, nil
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, tr.CloseIdleConnections
}

// fetchFavicon 取 /favicon.ico 并算 mmh3 哈希；失败静默返回空串（指纹是加分项，不是必需项）。
func (s *Scanner) fetchFavicon(ctx context.Context, ip string, port int, scheme string, opt FingerprintOptions, fp *Fingerprint) string {
	client, closeFn := s.httpClientFor(ip, port, opt, fp)
	defer closeFn()

	url := scheme + "://" + net.JoinHostPort(ip, itoa(port)) + "/favicon.ico"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || len(data) == 0 {
		return ""
	}
	return faviconHash(data)
}

// grabBanner 抓非 HTTP 服务的首包（需要时先发只读探针）。
func (s *Scanner) grabBanner(ctx context.Context, ip string, port int, timeout time.Duration, fp *Fingerprint) string {
	bctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := s.dialTCP(bctx, ip, port, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// TLS 服务（如 LDAPS / IMAPS）：先握手，证书本身就是指纹
	if tlsPorts[port] || (fp != nil && fp.TLS) {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
		if err := tc.HandshakeContext(bctx); err != nil {
			return ""
		}
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 && fp != nil {
			fp.TLS = true
			applyCertState(fp, &st)
		}
		conn = tc
	}

	if dl, ok := bctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}
	if p, ok := bannerProbes[port]; ok && p != "" {
		_, _ = conn.Write([]byte(p))
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

// sanitizeBanner 清洗 banner：MySQL 等服务的首包是二进制，
// 直接入库会污染 JSON 与前端渲染，所以非可打印字符统一替换为空格。
func sanitizeBanner(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, c := range raw {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			b.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			b.WriteByte(' ')
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// applyCertState 提取证书里的资产情报。
func applyCertState(fp *Fingerprint, st *tls.ConnectionState) {
	if fp == nil || st == nil || len(st.PeerCertificates) == 0 {
		return
	}
	c := st.PeerCertificates[0]
	fp.TLSCN = strings.TrimSpace(c.Subject.CommonName)
	fp.CertIssuer = strings.TrimSpace(c.Issuer.CommonName)
	if fp.CertIssuer == "" && len(c.Issuer.Organization) > 0 {
		fp.CertIssuer = strings.TrimSpace(c.Issuer.Organization[0])
	}
	fp.CertExpiry = c.NotAfter.Format("2006-01-02")
	fp.SelfSigned = c.Subject.String() == c.Issuer.String()

	names := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	seen := map[string]bool{}
	for _, d := range c.DNSNames {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		names = append(names, d)
	}
	// 证书里写 IP SAN 的设备（大量摄像头 / 网络设备）同样有价值
	for _, ip := range c.IPAddresses {
		s := ip.String()
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		names = append(names, s)
	}
	if len(names) > 0 {
		fp.TLSNames = names
	}
}
