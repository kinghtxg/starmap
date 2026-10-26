package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 辅助 ----------

func newFPScanner(t *testing.T) *Scanner {
	t.Helper()
	s, _ := newTestScanner()
	s.NowFunc = time.Now
	s.SetRate(0)
	return s
}

// serverPort 从 httptest 服务地址里取出端口。
func serverPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}
	_, ps, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("拆分地址失败: %v", err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatalf("端口不是数字: %v", err)
	}
	return p
}

func fpOpts() FingerprintOptions {
	o := DefaultFingerprintOptions()
	o.Timeout = 2 * time.Second
	return o
}

// ---------- murmur3 / favicon ----------

func TestMurmur3KnownVectors(t *testing.T) {
	// 与社区实现（python-mmh3）对齐的已知值：算错了 favicon 指纹库就完全对不上
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"a", 1009084850},
		{"foo", 4138058784}, // 有符号表示 -156908512
		{"hello", 613153351},
	}
	for _, c := range cases {
		if got := murmur3_32([]byte(c.in), 0); got != c.want {
			t.Errorf("murmur3_32(%q) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

func TestMurmur3SeedDiffers(t *testing.T) {
	if murmur3_32([]byte("starmap"), 0) == murmur3_32([]byte("starmap"), 1) {
		t.Error("不同 seed 应得到不同结果")
	}
}

func TestFaviconHash(t *testing.T) {
	if got := faviconHash(nil); got != "" {
		t.Errorf("空内容应返回空串，实际 %q", got)
	}
	a := faviconHash([]byte{0x00, 0x00, 0x01, 0x00, 0xff, 0xd8})
	b := faviconHash([]byte{0x00, 0x00, 0x01, 0x00, 0xff, 0xd8})
	if a == "" || a != b {
		t.Errorf("同一内容应得到稳定哈希：%q / %q", a, b)
	}
	c := faviconHash([]byte{0x00, 0x00, 0x01, 0x00, 0xff, 0xd9})
	if a == c {
		t.Error("不同内容不应得到相同哈希")
	}
	// 有符号 32 位格式（可能带负号），必须是可解析的整数
	if _, err := strconv.ParseInt(a, 10, 32); err != nil {
		t.Errorf("favicon 哈希 %q 不是合法 int32: %v", a, err)
	}
	// 超过 76 字符的 base64 会被换行，此处验证长内容不会 panic 且稳定
	long := make([]byte, 600)
	for i := range long {
		long[i] = byte(i)
	}
	if x, y := faviconHash(long), faviconHash(long); x != y || x == "" {
		t.Errorf("长内容哈希不稳定: %q / %q", x, y)
	}
}

// ---------- 选项与文本处理 ----------

func TestFingerprintOptionsNormalize(t *testing.T) {
	cases := []struct{ in, want FingerprintOptions }{
		{FingerprintOptions{}, FingerprintOptions{Timeout: 3 * time.Second, MaxBody: 64 << 10}},
		{FingerprintOptions{Timeout: -time.Second, MaxBody: -1}, FingerprintOptions{Timeout: 3 * time.Second, MaxBody: 64 << 10}},
		{FingerprintOptions{Timeout: time.Minute, MaxBody: 1 << 30}, FingerprintOptions{Timeout: 30 * time.Second, MaxBody: 1 << 20}},
	}
	for _, c := range cases {
		got := c.in.normalize()
		if got.Timeout != c.want.Timeout || got.MaxBody != c.want.MaxBody {
			t.Errorf("%+v normalize = %+v，期望 %+v", c.in, got, c.want)
		}
	}
	def := DefaultFingerprintOptions()
	if def.Timeout != 3*time.Second || !def.FetchFavicon || def.MaxBody != 64<<10 {
		t.Errorf("默认选项 = %+v", def)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := []struct{ in, want string }{
		{`<html><head><title>登录 - 泛微OA</title></head>`, "登录 - 泛微OA"},
		{"<TITLE>UPPER</TITLE>", "UPPER"},
		{`<title class="x" data-a="1">带属性</title>`, "带属性"},
		{`<title>A &amp; B &lt;2&gt;</title>`, "A & B <2>"},
		{"<title>\n  多  空\n 白 </title>", "多 空 白"},
		{"<html><body>无标题</body></html>", ""},
		{"<title></title>", ""},
	}
	for _, c := range cases {
		if got := extractTitle(c.in); got != c.want {
			t.Errorf("extractTitle(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
	// 超长标题截断到 200，避免把整段 HTML 当标题写进台账
	long := "<title>" + strings.Repeat("x", 500) + "</title>"
	if got := extractTitle(long); len(got) != 200 {
		t.Errorf("超长标题长度 = %d，期望截断到 200", len(got))
	}
}

func TestSanitizeBanner(t *testing.T) {
	// MySQL 首包是二进制，直接入库会污染 JSON 与前端
	got := sanitizeBanner([]byte{'J', 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', 0x1f, '\r', '\n'})
	if strings.ContainsAny(got, "\r\n\x00\x1f") {
		t.Errorf("清洗后仍含控制字符: %q", got)
	}
	if !strings.Contains(got, "8.0") {
		t.Errorf("可打印内容应保留，实际 %q", got)
	}
	if strings.TrimSpace(sanitizeBanner([]byte("  a   b  \r\n"))) != "a b" {
		t.Errorf("连续空白应压缩，实际 %q", sanitizeBanner([]byte("  a   b  \r\n")))
	}
	long := sanitizeBanner([]byte(strings.Repeat("y", 900)))
	if len(long) != 200 {
		t.Errorf("超长 banner 长度 = %d，期望 200", len(long))
	}
	if sanitizeBanner(nil) != "" {
		t.Error("空 banner 应返回空串")
	}
}

func TestGuessService(t *testing.T) {
	cases := []struct {
		port  int
		isWeb bool
		isTLS bool
		want  string
	}{
		{22, false, false, "ssh"},
		{3306, false, false, "mysql"},
		{6379, false, false, "redis"},
		{3389, false, false, "rdp"},
		{80, true, false, "http"},
		{443, true, true, "https"},
		{8080, true, false, "http"},
		{12345, true, false, "http"},
		{12345, true, true, "https"},
		{12345, false, true, "tls"},
		{12345, false, false, ""},
	}
	for _, c := range cases {
		if got := guessService(c.port, c.isWeb, c.isTLS); got != c.want {
			t.Errorf("guessService(%d,%v,%v) = %q，期望 %q", c.port, c.isWeb, c.isTLS, got, c.want)
		}
	}
}

// ---------- 规则匹配 ----------

func TestMatchRules(t *testing.T) {
	cases := []struct {
		name        string
		in          ruleInput
		wantProduct string
		wantVersion string
		wantService string
	}{
		{
			name:        "nginx 版本",
			in:          ruleInput{header: "server: nginx/1.18.0 (ubuntu)", port: 80},
			wantProduct: "nginx", wantVersion: "1.18.0", wantService: "http",
		},
		{
			name:        "openresty 优先于 nginx",
			in:          ruleInput{header: "server: openresty/1.21.4.1"},
			wantProduct: "OpenResty", wantVersion: "1.21.4.1", wantService: "http",
		},
		{
			name:        "IIS 版本",
			in:          ruleInput{header: "server: microsoft-iis/10.0"},
			wantProduct: "Microsoft IIS", wantVersion: "10.0", wantService: "http",
		},
		{
			name:        "泛微 e-cology 靠静态路径识别",
			in:          ruleInput{body: `<a href="/wui/index.html">`, title: "登录"},
			wantProduct: "泛微 e-cology", wantService: "http",
		},
		{
			name:        "致远 OA",
			in:          ruleInput{body: "location.href='/seeyon/main.do'"},
			wantProduct: "致远 OA", wantService: "http",
		},
		{
			name:        "海康威视 设备",
			in:          ruleInput{body: "dvrdvs", title: "网络摄像机"},
			wantProduct: "海康威视 设备", wantService: "http",
		},
		{
			name:        "OpenSSH banner",
			in:          ruleInput{banner: "ssh-2.0-openssh_8.9p1 ubuntu-3ubuntu0.1", port: 22},
			wantProduct: "OpenSSH", wantVersion: "8.9p1", wantService: "ssh",
		},
		{
			name:        "非 OpenSSH 的 SSH",
			in:          ruleInput{banner: "ssh-2.0-dropbear_2020.81", port: 22},
			wantProduct: "SSH", wantService: "ssh",
		},
		{
			// banner 里的 "cisco" 不能当成 Web 设备指纹：否则一台 SSH 服务会被标成
			// "Cisco 设备 / http"，服务名错了比产品名缺失更难排查
			name:        "厂商名出现在 SSH 标识里不误判为 Web 设备",
			in:          ruleInput{banner: "ssh-2.0-cisco-1.25", port: 22},
			wantProduct: "SSH", wantService: "ssh",
		},
		{
			name:        "vsftpd 带版本",
			in:          ruleInput{banner: "220 (vsftpd 3.0.3)", port: 21},
			wantProduct: "vsftpd", wantVersion: "3.0.3", wantService: "ftp",
		},
		{
			name:        "MariaDB 优先于 MySQL",
			in:          ruleInput{banner: "5.5.5-10.4.28-mariadb", port: 3306},
			wantProduct: "MariaDB", wantService: "mysql",
		},
		{
			name:        "Redis +PONG",
			in:          ruleInput{banner: "+pong", port: 6379},
			wantProduct: "Redis", wantService: "redis",
		},
		{
			name:        "Jenkins 标题",
			in:          ruleInput{title: "dashboard [jenkins]"},
			wantProduct: "Jenkins", wantService: "http",
		},
		{
			name:        "Tomcat",
			in:          ruleInput{body: `<title>Apache Tomcat/9.0.65</title>`, title: "apache tomcat/9.0.65"},
			wantProduct: "Apache Tomcat", wantService: "http",
		},
		{
			name:        "Spring Boot 默认错误页",
			in:          ruleInput{title: "whitelabel error page"},
			wantProduct: "Spring Boot", wantService: "http",
		},
		{
			name:        "未命中返回空",
			in:          ruleInput{body: "<html>hello world</html>", port: 80},
			wantProduct: "", wantService: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, v, svc := matchRules(c.in)
			if p != c.wantProduct {
				t.Errorf("产品 = %q，期望 %q", p, c.wantProduct)
			}
			if c.wantVersion != "" && v != c.wantVersion {
				t.Errorf("版本 = %q，期望 %q", v, c.wantVersion)
			}
			if svc != c.wantService {
				t.Errorf("服务 = %q，期望 %q", svc, c.wantService)
			}
		})
	}
}

// 限定端口的规则不能在别的端口上误命中（否则一台 8080 上的 ES 客户端页面
// 会被写成"Elasticsearch 服务器"）。
func TestRulePortRestriction(t *testing.T) {
	in := ruleInput{body: "you know, for search", port: 8080}
	if p, _, _ := matchRules(in); p == "Elasticsearch" {
		t.Error("8080 端口不应命中 Elasticsearch 规则")
	}
	in.port = 9200
	if p, _, _ := matchRules(in); p != "Elasticsearch" {
		t.Errorf("9200 端口应命中 Elasticsearch，实际 %q", p)
	}
}

// 规则表自身的一致性检查：产品名不重复、版本正则都能编译、必有服务名。
func TestRuleTableSane(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range fpRules {
		if r.Product == "" {
			t.Error("存在没有产品名的规则")
		}
		if seen[r.Product] {
			t.Errorf("产品名重复: %q（后者永远不会命中）", r.Product)
		}
		seen[r.Product] = true
		if r.Service == "" {
			t.Errorf("%q 缺少服务名", r.Product)
		}
		if len(r.Any) == 0 && len(r.Title) == 0 && len(r.Header) == 0 {
			t.Errorf("%q 没有任何匹配条件（永远不会命中）", r.Product)
		}
		if r.Version != "" && r.verRE == nil {
			t.Errorf("%q 的版本正则未编译", r.Product)
		}
		// 匹配串统一小写，否则永远匹配不上被转小写的输入
		for _, s := range append(append([]string{}, r.Any...), r.Title...) {
			if s != strings.ToLower(s) {
				t.Errorf("%q 的匹配串 %q 含大写字母（输入已小写，永远不命中）", r.Product, s)
			}
		}
	}
}

// ---------- HTTP 指纹 ----------

func TestFingerprintHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x02, 0x00})
			return
		}
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte(`<html><head><title>政务OA 登录</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", serverPort(t, srv.URL), fpOpts())
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if fp.Product != "nginx" || fp.Version != "1.18.0" {
		t.Errorf("产品/版本 = %q/%q，期望 nginx/1.18.0", fp.Product, fp.Version)
	}
	if fp.Title != "政务OA 登录" {
		t.Errorf("标题 = %q", fp.Title)
	}
	if fp.Server != "nginx/1.18.0" {
		t.Errorf("Server = %q", fp.Server)
	}
	if fp.Status != http.StatusOK {
		t.Errorf("状态码 = %d", fp.Status)
	}
	if fp.Service != "http" {
		t.Errorf("服务 = %q", fp.Service)
	}
	if fp.Favicon == "" {
		t.Error("应给出 favicon 哈希")
	}
	if fp.TLS {
		t.Error("明文服务不应标记 TLS")
	}
}

func TestFingerprintFaviconStable(t *testing.T) {
	icon := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write(icon)
			return
		}
		_, _ = w.Write([]byte("<html><title>t</title></html>"))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	port := serverPort(t, srv.URL)
	fp1, err := s.Fingerprint(context.Background(), "127.0.0.1", port, fpOpts())
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	want := faviconHash(icon)
	if fp1.Favicon != want {
		t.Errorf("favicon = %q，期望 %q", fp1.Favicon, want)
	}
	// 关掉 favicon 抓取就不该再发这个请求
	opt := fpOpts()
	opt.FetchFavicon = false
	fp2, err := s.Fingerprint(context.Background(), "127.0.0.1", port, opt)
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if fp2.Favicon != "" {
		t.Errorf("关闭 favicon 后仍得到 %q", fp2.Favicon)
	}
}

// 401/403 的登录页同样是高价值指纹：不能因为状态码不是 200 就放弃识别。
func TestFingerprintAuthPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="H3C"`)
		w.Header().Set("Server", "H3C-Server")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><title>H3C 登录</title>Comware Software</html>`))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", serverPort(t, srv.URL), fpOpts())
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if fp.Status != http.StatusUnauthorized {
		t.Errorf("状态码 = %d，期望 401", fp.Status)
	}
	if fp.Product != "H3C 设备" {
		t.Errorf("产品 = %q，期望 H3C 设备", fp.Product)
	}
}

func TestFingerprintRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://oa.internal.gov.cn/login", http.StatusFound)
	}))
	defer srv.Close()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", serverPort(t, srv.URL), fpOpts())
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if fp.Status != http.StatusFound {
		t.Errorf("状态码 = %d，期望 302", fp.Status)
	}
	// 跳转地址往往直接暴露真实域名，是最有价值的一条情报
	if !strings.Contains(fp.Location, "oa.internal.gov.cn") {
		t.Errorf("Location = %q，应保留跳转地址", fp.Location)
	}
}

// 不认识的小服务：HTTP 探测失败后应能靠 banner 兜底。
func TestFingerprintNonHTTPService(t *testing.T) {
	orig := shouldGrabBanner
	shouldGrabBanner = func(int) bool { return true }
	defer func() { shouldGrabBanner = orig }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ { // http / https / banner 各一次
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_7.4\r\n"))
			_ = c.Close()
		}
	}()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", port, fpOpts())
	wg.Wait()
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if fp.Product != "OpenSSH" || fp.Version != "7.4" {
		t.Errorf("产品/版本 = %q/%q，期望 OpenSSH/7.4", fp.Product, fp.Version)
	}
	if !strings.Contains(fp.Banner, "OpenSSH_7.4") {
		t.Errorf("banner = %q", fp.Banner)
	}
	if fp.Status != 0 {
		t.Errorf("非 HTTP 服务状态码应为 0，实际 %d", fp.Status)
	}
}

func TestFingerprintNoResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // 连得上也拿不到任何东西 → 退化成 connection refused

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", port, fpOpts())
	if err == nil {
		t.Fatalf("无响应端口应返回错误，实际 %+v", fp)
	}
	if fp != nil {
		t.Errorf("出错时不应返回半成品指纹: %+v", fp)
	}
	if !strings.Contains(err.Error(), "无可识别的应用层响应") {
		t.Errorf("错误信息 = %q", err.Error())
	}
}

func TestFingerprintContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("<html><title>slow</title></html>"))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := s.Fingerprint(ctx, "127.0.0.1", serverPort(t, srv.URL), fpOpts())
	if err == nil {
		t.Fatal("已取消的上下文应返回错误")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("取消后耗时 %v，没有及时中断", d)
	}
}

// ---------- TLS 指纹 ----------

func TestFingerprintTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.20.1")
		_, _ = w.Write([]byte("<html><title>内网系统</title></html>"))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", serverPort(t, srv.URL), objNoFavicon())
	if err != nil {
		t.Fatalf("TLS 指纹失败: %v", err)
	}
	if !fp.TLS {
		t.Fatal("应标记为 TLS 服务")
	}
	if fp.Title != "内网系统" {
		t.Errorf("标题 = %q", fp.Title)
	}
	// 现代证书常常只写 SAN、CN 留空——所以判据放在 SAN 上，CN 允许为空
	if !containsStr(fp.TLSNames, "example.com") {
		t.Errorf("证书 SAN = %v，应含 example.com", fp.TLSNames)
	}
	if !fp.SelfSigned {
		t.Error("httptest 证书是自签的，自我签发标记应为 true")
	}
	if fp.CertExpiry == "" {
		t.Error("应给出证书到期日")
	}
	if fp.Service != "http" {
		t.Errorf("服务 = %q（应由规则给出 http）", fp.Service)
	}
}

// 内网大量 8443/8080 上挂的是 TLS，明文优先的顺序不能把它漏掉。
func TestFingerprintTLSOnHighPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>tls-on-high-port</title></html>"))
	}))
	defer srv.Close()

	s := newFPScanner(t)
	fp, err := s.Fingerprint(context.Background(), "127.0.0.1", serverPort(t, srv.URL), objNoFavicon())
	if err != nil {
		t.Fatalf("指纹失败: %v", err)
	}
	if !fp.TLS || fp.Title != "tls-on-high-port" {
		t.Errorf("高位端口 TLS 识别失败: %+v", fp)
	}
}

func TestApplyCertState(t *testing.T) {
	fp := &Fingerprint{}
	applyCertState(fp, nil) // 不应 panic
	applyCertState(nil, &tls.ConnectionState{})
	if fp.TLS || fp.TLSCN != "" {
		t.Error("空输入不应写入任何字段")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS 连接失败: %v", err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	fp2 := &Fingerprint{}
	applyCertState(fp2, &st)
	if len(fp2.TLSNames) == 0 && fp2.TLSCN == "" {
		t.Errorf("证书既没有 CN 也没有 SAN: %+v", fp2)
	}
	if fp2.CertIssuer == "" || fp2.CertExpiry == "" {
		t.Errorf("证书签发者/到期日缺失: %+v", fp2)
	}
	// SAN 去重
	dup := map[string]int{}
	for _, n := range fp2.TLSNames {
		dup[n]++
	}
	for n, c := range dup {
		if c > 1 {
			t.Errorf("SAN %q 重复出现 %d 次", n, c)
		}
	}
}

// ---------- 小工具 ----------

func objNoFavicon() FingerprintOptions {
	o := fpOpts()
	o.FetchFavicon = false
	return o
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
