package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// 假身份源（APSSO）：一个 httptest.Server 同时扮演发现文档 / JWKS / 令牌端点 / userinfo。
//
// 为什么值得为它写这么多代码：OIDC 回调是整条鉴权链上唯一「信任外部输入」的地方——
// state 校验、PKCE、ID Token 验签、iss/aud/exp 校验任何一环被绕过，
// 就等于把登录页送给任何人。而它此前没有任何测试。
// ---------------------------------------------------------------------------

type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	// 行为开关（按需在用例里改）
	metaStatus    int
	omitUserinfo  bool
	tokenStatus   int
	tokenBody     map[string]any
	noIDToken     bool
	algOverride   string
	expOverride   int64
	issOverride   string
	audOverride   any
	signKey       *rsa.PrivateKey
	jwksStatus    int
	jwksEmpty     bool
	userinfoBody  map[string]any
	userinfoCode  int
	lastVerifier  string
	lastGrantType string
	metaHits      atomic.Int32
	jwksHits      atomic.Int32
	tokenHits     atomic.Int32
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	f := &fakeIdP{
		key: key,
		kid: "test-kid-1",
		userinfoBody: map[string]any{
			"sub":                "u-1",
			"preferred_username": "张三",
			"groups":             []string{"运维"},
		},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.metaHits.Add(1)
		if f.metaStatus != 0 {
			w.WriteHeader(f.metaStatus)
			return
		}
		body := map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks",
		}
		if !f.omitUserinfo {
			body["userinfo_endpoint"] = f.srv.URL + "/userinfo"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		if f.jwksStatus != 0 {
			w.WriteHeader(f.jwksStatus)
			return
		}
		if f.jwksEmpty {
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		pub := &f.key.PublicKey
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"` + f.kid + `","alg":"RS256","n":"` +
			base64.RawURLEncoding.EncodeToString(pub.N.Bytes()) + `","e":"` +
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()) + `"}]}`))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits.Add(1)
		_ = r.ParseForm()
		f.lastVerifier = r.PostForm.Get("code_verifier")
		f.lastGrantType = r.PostForm.Get("grant_type")
		if f.tokenStatus != 0 {
			w.WriteHeader(f.tokenStatus)
			return
		}
		if f.tokenBody != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.tokenBody)
			return
		}
		body := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}
		if !f.noIDToken {
			body["id_token"] = f.idToken()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if f.userinfoCode != 0 {
			w.WriteHeader(f.userinfoCode)
			return
		}
		if r.Header.Get("Authorization") != "Bearer at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.userinfoBody)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// idToken 按当前开关签发一个 ID Token。
func (f *fakeIdP) idToken() string {
	alg := "RS256"
	if f.algOverride != "" {
		alg = f.algOverride
	}
	iss := f.srv.URL
	if f.issOverride != "" {
		iss = f.issOverride
	}
	var aud any = "starmap-web"
	if f.audOverride != nil {
		aud = f.audOverride
	}
	exp := time.Now().Add(time.Hour).Unix()
	if f.expOverride != 0 {
		exp = f.expOverride
	}
	claims := map[string]any{
		"iss":                iss,
		"sub":                "u-1",
		"aud":                aud,
		"exp":                exp,
		"iat":                time.Now().Unix(),
		"preferred_username": "张三",
		"roles":              []string{"admin"},
	}
	hb, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": f.kid})
	pb, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	key := f.key
	if f.signKey != nil {
		key = f.signKey
	}
	var sig []byte
	if alg == "RS256" {
		digest := sha256.Sum256([]byte(signing))
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
	} else {
		sig = []byte("not-a-real-signature")
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func oidcRuntime(t *testing.T, idp *fakeIdP) *runtime {
	t.Helper()
	return sessionRT(t, Config{
		Mode: ModeOIDC,
		OIDC: OIDCConfig{
			Issuer:       idp.srv.URL,
			ClientID:     "starmap-web",
			ClientSecret: "s3cret",
			ProviderName: "APSSO",
			Scopes:       []string{"openid", "profile", "email"},
		},
	})
}

func oidcEngine(rt *runtime) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(rt.middleware())
	registerRoutes(r, rt)
	r.GET("/assets.html", func(c *gin.Context) { c.String(http.StatusOK, "page") })
	return r
}

// startFlow 发起一次 OIDC 登录，返回 state Cookie 与 state 值。
func startFlow(t *testing.T, r *gin.Engine, next string) (*http.Cookie, string) {
	t.Helper()
	target := "/api/auth/oidc/start"
	if next != "" {
		target += "?" + returnToParam + "=" + url.QueryEscape(next)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("oidc/start 应 302，实际 %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("跳转地址无法解析: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("缺少 state")
	}
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	if len(cookies) == 0 || cookies[0].Name != stateCookieName {
		t.Fatalf("未写入 state Cookie: %+v", cookies)
	}
	return cookies[0], state
}

// TestOIDCAuthorizationCodeFlow 完整走一遍：start（state+PKCE）→ callback → 会话。
func TestOIDCAuthorizationCodeFlow(t *testing.T) {
	idp := newFakeIdP(t)
	rt := oidcRuntime(t, idp)
	r := oidcEngine(rt)

	// --- 1. start：授权地址必须带 PKCE S256、state、scope ---
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?"+returnToParam+"=/assets.html", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start 应 302，实际 %d %s", w.Code, w.Body.String())
	}
	if idp.metaHits.Load() != 1 {
		t.Fatalf("应请求 1 次发现文档，实际 %d", idp.metaHits.Load())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("解析跳转地址失败: %v", err)
	}
	if !strings.HasPrefix(loc.String(), idp.srv.URL+"/authorize?") {
		t.Fatalf("跳转目标不是授权端点: %s", loc)
	}
	q := loc.Query()
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type 应为 code，实际 %q", q.Get("response_type"))
	}
	if q.Get("client_id") != "starmap-web" {
		t.Fatalf("client_id 不符: %q", q.Get("client_id"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatal("必须使用 PKCE S256")
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("缺少 code_challenge")
	}
	if q.Get("scope") != "openid profile email" {
		t.Fatalf("scope 不符: %q", q.Get("scope"))
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), "/api/auth/callback") {
		t.Fatalf("redirect_uri 未按请求推导: %q", q.Get("redirect_uri"))
	}
	stateCookie := (&http.Response{Header: w.Header()}).Cookies()[0]
	if !stateCookie.HttpOnly {
		t.Fatal("state Cookie 必须 HttpOnly")
	}

	// --- 2. callback：带 code + state + state Cookie ---
	cw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?code=abc&state="+q.Get("state"), nil)
	req.AddCookie(stateCookie)
	r.ServeHTTP(cw, req)
	if cw.Code != http.StatusFound {
		t.Fatalf("callback 应 302，实际 %d %s", cw.Code, cw.Body.String())
	}
	if got := cw.Header().Get("Location"); got != "/assets.html" {
		t.Fatalf("未按 next 回跳，实际 %q", got)
	}
	if idp.lastGrantType != "authorization_code" {
		t.Fatalf("grant_type 不符: %q", idp.lastGrantType)
	}
	if idp.lastVerifier == "" {
		t.Fatal("令牌交换未带 code_verifier（PKCE 失效）")
	}

	cookies := (&http.Response{Header: cw.Header()}).Cookies()
	var session *http.Cookie
	for _, ck := range cookies {
		if ck.Name == rt.cfg.CookieName {
			session = ck
		}
	}
	if session == nil {
		t.Fatalf("回调未签发会话 Cookie: %+v", cookies)
	}
	claims, ok := rt.verify(session.Value)
	if !ok {
		t.Fatal("签发的会话必须能自校验")
	}
	if claims.Sub != "u-1" || claims.Role != RoleAdmin || claims.Via != ModeOIDC {
		t.Fatalf("会话内容不符: %+v", claims)
	}
	if claims.Name != "张三" {
		t.Fatalf("展示名应取 preferred_username，实际 %q", claims.Name)
	}

	// --- 3. 会话确实能开门 ---
	pw := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodGet, "/assets.html", nil)
	preq.AddCookie(session)
	r.ServeHTTP(pw, preq)
	if pw.Code != http.StatusOK {
		t.Fatalf("带会话应放行，实际 %d", pw.Code)
	}
}

// TestOIDCUserInfoFallback 身份源只给 access_token（无 id_token）时走 userinfo。
func TestOIDCUserInfoFallback(t *testing.T) {
	idp := newFakeIdP(t)
	idp.noIDToken = true
	rt := oidcRuntime(t, idp)
	r := oidcEngine(rt)

	stateCookie, state := startFlow(t, r, "")
	cw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?code=abc&state="+state, nil)
	req.AddCookie(stateCookie)
	r.ServeHTTP(cw, req)
	if cw.Code != http.StatusFound {
		t.Fatalf("callback 应 302，实际 %d %s", cw.Code, cw.Body.String())
	}
	var session *http.Cookie
	for _, ck := range (&http.Response{Header: cw.Header()}).Cookies() {
		if ck.Name == rt.cfg.CookieName {
			session = ck
		}
	}
	if session == nil {
		t.Fatal("未签发会话")
	}
	claims, _ := rt.verify(session.Value)
	if claims.Role != RoleOperator {
		t.Fatalf("groups=[运维] 应解析为 operator，实际 %q", claims.Role)
	}
	if claims.Name != "张三" {
		t.Fatalf("展示名不符: %q", claims.Name)
	}
}

// TestOIDCCallbackRejects 回调链路上的每一道校验都必须真的拦得住。
func TestOIDCCallbackRejects(t *testing.T) {
	cases := []struct {
		name    string
		knob    func(*fakeIdP)
		query   func(state string) string
		noState bool
		// cookieVal / queryState 留空表示用 startFlow 拿到的真实 state。
		// 两者拆开是为了分别构造「Cookie 与查询不一致」和「state 无对应流程」。
		cookieVal  string
		queryState string
		want       int
		wantHas    string
	}{
		{
			name:  "身份源回传 error",
			query: func(string) string { return "?error=access_denied&error_description=user%20cancelled" },
			want:  http.StatusBadGateway, wantHas: "拒绝了本次登录",
		},
		{
			name:  "缺少 code",
			query: func(s string) string { return "?state=" + s },
			want:  http.StatusBadRequest, wantHas: "回调参数不完整",
		},
		{
			name:    "缺少 state Cookie",
			query:   func(s string) string { return "?code=abc&state=" + s },
			noState: true,
			want:    http.StatusBadRequest, wantHas: "登录状态已失效",
		},
		{
			name:      "state Cookie 与查询不一致",
			query:     func(s string) string { return "?code=abc&state=" + s },
			cookieVal: "forged-state",
			want:      http.StatusBadRequest, wantHas: "state 校验失败",
		},
		{
			name:       "state 无对应流程（过期/伪造）",
			query:      func(string) string { return "?code=abc&state=deadbeef" },
			cookieVal:  "deadbeef",
			queryState: "deadbeef",
			want:       http.StatusBadRequest, wantHas: "登录状态已过期",
		},
		{
			name:  "令牌端点 500",
			knob:  func(f *fakeIdP) { f.tokenStatus = http.StatusInternalServerError },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份服务不可达",
		},
		{
			name: "令牌端点返回 error",
			knob: func(f *fakeIdP) {
				f.tokenBody = map[string]any{"error": "invalid_grant", "error_description": "code expired"}
			},
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份服务不可达",
		},
		{
			name: "ID Token 签名不匹配（另一把私钥）",
			knob: func(f *fakeIdP) {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					panic(err)
				}
				f.signKey = other
			},
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "ID Token 已过期",
			knob:  func(f *fakeIdP) { f.expOverride = time.Now().Add(-time.Minute).Unix() },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "ID Token 受众不符",
			knob:  func(f *fakeIdP) { f.audOverride = "another-app" },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "ID Token 签发者不符",
			knob:  func(f *fakeIdP) { f.issOverride = "https://evil.example.com" },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "不支持的签名算法",
			knob:  func(f *fakeIdP) { f.algOverride = "HS256" },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "alg=none 不得放行",
			knob:  func(f *fakeIdP) { f.algOverride = "none" },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "JWKS 为空",
			knob:  func(f *fakeIdP) { f.jwksEmpty = true },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "无 id_token 且无 userinfo 端点",
			knob:  func(f *fakeIdP) { f.noIDToken = true; f.omitUserinfo = true },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
		{
			name:  "userinfo 拒绝",
			knob:  func(f *fakeIdP) { f.noIDToken = true; f.userinfoCode = http.StatusUnauthorized },
			query: func(s string) string { return "?code=abc&state=" + s },
			want:  http.StatusServiceUnavailable, wantHas: "身份校验失败",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			if tc.knob != nil {
				tc.knob(idp)
			}
			rt := oidcRuntime(t, idp)
			r := oidcEngine(rt)

			// 需要流程的用例先真正 start 一次，拿到 state 与 Cookie
			stateCookie, realState := startFlow(t, r, "")
			qState := realState
			if tc.queryState != "" {
				qState = tc.queryState
			}
			if tc.cookieVal != "" {
				stateCookie = &http.Cookie{Name: stateCookieName, Value: tc.cookieVal}
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/callback"+tc.query(qState), nil)
			if !tc.noState {
				req.AddCookie(stateCookie)
			}
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("期望 %d，实际 %d: %s", tc.want, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantHas) {
				t.Fatalf("错误页应包含 %q，实际: %s", tc.wantHas, w.Body.String())
			}
			// 任何失败路径都不得签发会话
			for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
				if ck.Name == rt.cfg.CookieName && ck.Value != "" {
					t.Fatal("失败路径不应签发会话 Cookie")
				}
			}
		})
	}
}

// TestOIDCStartNotOIDCMode 非 oidc 模式访问 OIDC 端点应给出明确错误。
func TestOIDCStartNotOIDCMode(t *testing.T) {
	rt := sessionRT(t, Config{Mode: ModeLocal, LocalUsers: []LocalUser{{Username: "ops", PasswordBcrypt: dummyHash()}}})
	r := oidcEngine(rt)
	for _, p := range []string{"/api/auth/oidc/start", "/api/auth/callback?code=a&state=b"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d", p, w.Code)
		}
		if !strings.Contains(w.Body.String(), "未启用 OIDC") {
			t.Fatalf("%s 错误页内容不符: %s", p, w.Body.String())
		}
	}
}

// TestOIDCStartUnreachable 身份服务不可达 → 503，绝不静默放行（§7.5 降级）。
func TestOIDCStartUnreachable(t *testing.T) {
	rt := sessionRT(t, Config{Mode: ModeOIDC, OIDC: OIDCConfig{
		Issuer: "http://127.0.0.1:1", ClientID: "starmap-web", TimeoutSeconds: 2,
	}})
	r := oidcEngine(rt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("应 503，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "身份服务不可达") {
		t.Fatalf("错误页内容不符: %s", w.Body.String())
	}
}

// TestOIDCClientMetadata 发现文档的失败分支与缓存行为。
func TestOIDCClientMetadata(t *testing.T) {
	if _, err := newOIDCClient(OIDCConfig{}).metadata(t.Context()); err != errNotConfigured {
		t.Fatalf("未配置 issuer 应返回 errNotConfigured，实际 %v", err)
	}

	idp := newFakeIdP(t)
	o := newOIDCClient(OIDCConfig{Issuer: idp.srv.URL, ClientID: "c", TimeoutSeconds: 5})
	// 首次：正常
	if _, err := o.metadata(t.Context()); err != nil {
		t.Fatalf("发现文档应可获取: %v", err)
	}
	// 二次：缓存命中，不再发请求
	if _, err := o.metadata(t.Context()); err != nil {
		t.Fatalf("缓存读取失败: %v", err)
	}
	if idp.metaHits.Load() != 1 {
		t.Fatalf("发现文档应缓存，实际请求 %d 次", idp.metaHits.Load())
	}

	// 500
	bad := newFakeIdP(t)
	bad.metaStatus = http.StatusInternalServerError
	if _, err := newOIDCClient(OIDCConfig{Issuer: bad.srv.URL, TimeoutSeconds: 5}).metadata(t.Context()); err == nil {
		t.Fatal("发现文档 500 应报错")
	}

	// 缺端点
	pm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"x"}`))
	}))
	defer pm.Close()
	if _, err := newOIDCClient(OIDCConfig{Issuer: pm.URL, TimeoutSeconds: 5}).metadata(t.Context()); err == nil {
		t.Fatal("发现文档缺端点应报错")
	}
}

// TestOIDCClientJWKS JWKS 的缓存与失败分支。
func TestOIDCClientJWKS(t *testing.T) {
	idp := newFakeIdP(t)
	o := newOIDCClient(OIDCConfig{Issuer: idp.srv.URL, ClientID: "c", TimeoutSeconds: 5})
	uri := idp.srv.URL + "/jwks"
	set, err := o.jwks(t.Context(), uri)
	if err != nil {
		t.Fatalf("JWKS 应可获取: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != idp.kid {
		t.Fatalf("JWKS 内容不符: %+v", set)
	}
	if _, err := o.jwks(t.Context(), uri); err != nil {
		t.Fatalf("缓存读取失败: %v", err)
	}
	if idp.jwksHits.Load() != 1 {
		t.Fatalf("JWKS 应缓存 1 小时，实际请求 %d 次", idp.jwksHits.Load())
	}

	// 空 keys
	empty := newFakeIdP(t)
	empty.jwksEmpty = true
	if _, err := newOIDCClient(OIDCConfig{Issuer: empty.srv.URL, TimeoutSeconds: 5}).jwks(t.Context(), empty.srv.URL+"/jwks"); err == nil {
		t.Fatal("JWKS 为空应报错")
	}

	// 非 200
	bad := newFakeIdP(t)
	bad.jwksStatus = http.StatusForbidden
	if _, err := newOIDCClient(OIDCConfig{Issuer: bad.srv.URL, TimeoutSeconds: 5}).jwks(t.Context(), bad.srv.URL+"/jwks"); err == nil {
		t.Fatal("JWKS 非 200 应报错")
	}
}

// TestPickKeyAndKeyDecode JWKS 选键与 JWK 参数解码的边界。
func TestPickKeyAndKeyDecode(t *testing.T) {
	only := &jwkSet{Keys: []jwk{{Kid: "a"}}}
	if _, ok := pickKey(only, ""); !ok {
		t.Fatal("单键且 kid 为空时应取唯一键")
	}
	multi := &jwkSet{Keys: []jwk{{Kid: "a"}, {Kid: "b"}}}
	if _, ok := pickKey(multi, ""); ok {
		t.Fatal("多键且 kid 为空时不应猜")
	}
	if k, ok := pickKey(multi, "b"); !ok || k.Kid != "b" {
		t.Fatal("应按 kid 精确选中")
	}
	if _, ok := pickKey(multi, "zzz"); ok {
		t.Fatal("kid 不存在应失败")
	}

	if _, err := rsaPublicKey(jwk{N: "!!!", E: "AQAB"}); err == nil {
		t.Fatal("非法 n 应报错")
	}
	if _, err := rsaPublicKey(jwk{N: "AQAB", E: "!!!"}); err == nil {
		t.Fatal("非法 e 应报错")
	}
	if _, err := rsaPublicKey(jwk{}); err == nil {
		t.Fatal("空参数应报错")
	}
	if _, err := ecPublicKey(jwk{X: "!!!", Y: "AQAB"}); err == nil {
		t.Fatal("非法 x 应报错")
	}
	if _, err := ecPublicKey(jwk{X: "AQAB", Y: "!!!"}); err == nil {
		t.Fatal("非法 y 应报错")
	}
}

// TestAudMatches aud 可能是字符串也可能是数组。
func TestAudMatches(t *testing.T) {
	if !audMatches(json.RawMessage(`"starmap"`), "starmap") {
		t.Fatal("字符串 aud 应匹配")
	}
	if !audMatches(json.RawMessage(`["a","starmap"]`), "starmap") {
		t.Fatal("数组 aud 应匹配")
	}
	if audMatches(json.RawMessage(`["a"]`), "starmap") {
		t.Fatal("数组 aud 不含 client_id 不应匹配")
	}
	if audMatches(nil, "starmap") {
		t.Fatal("空 aud 不应匹配")
	}
	if audMatches(json.RawMessage(`"starmap"`), "") {
		t.Fatal("空 client_id 不应匹配")
	}
}

// TestSafeNext 回跳地址只能本站相对路径（防开放重定向）。
func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"/assets.html":     "/assets.html",
		"/":                "/",
		"":                 "/",
		"   ":              "/",
		"//evil.com":       "/",
		"https://evil.com": "/",
		"evil":             "/",
		`/\evil.com`:       "/",
		"/deep/path?a=1":   "/deep/path?a=1",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Fatalf("safeNext(%q)=%q 期望 %q", in, got, want)
		}
	}
}

// TestSameOrigin Origin 存在时必须与 Host 一致（CSRF 防护）。
func TestSameOrigin(t *testing.T) {
	mk := func(origin, host string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "http://"+host+"/api/auth/login", nil)
		if origin != "" {
			c.Request.Header.Set("Origin", origin)
		}
		return c
	}
	if !sameOrigin(mk("", "sm.local")) {
		t.Fatal("无 Origin（非浏览器客户端）应放行")
	}
	if !sameOrigin(mk("http://sm.local", "sm.local")) {
		t.Fatal("同源应放行")
	}
	if sameOrigin(mk("http://evil.com", "sm.local")) {
		t.Fatal("跨站必须拒绝")
	}
	if sameOrigin(mk("://bad", "sm.local")) {
		t.Fatal("无法解析的 Origin 必须拒绝")
	}
}

// TestRedirectURI 回调地址：配置优先，否则按请求推导（含反代头）。
func TestRedirectURI(t *testing.T) {
	rt := sessionRT(t, Config{Mode: ModeOIDC, OIDC: OIDCConfig{
		Issuer: "http://idp", ClientID: "c", RedirectURL: "https://sm.example.com/api/auth/callback",
	}})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "http://internal:8080/api/auth/oidc/start", nil)
	if got := rt.redirectURI(c); got != "https://sm.example.com/api/auth/callback" {
		t.Fatalf("应优先用配置值，实际 %q", got)
	}

	rt2 := sessionRT(t, Config{Mode: ModeOIDC, OIDC: OIDCConfig{Issuer: "http://idp", ClientID: "c"}})
	if got := rt2.redirectURI(c); got != "http://internal:8080/api/auth/callback" {
		t.Fatalf("未配置时应按请求推导，实际 %q", got)
	}

	c.Request.Header.Set("X-Forwarded-Proto", "https")
	if got := rt2.redirectURI(c); got != "https://internal:8080/api/auth/callback" {
		t.Fatalf("应采信 X-Forwarded-Proto，实际 %q", got)
	}
}

// TestAuthConfigByMode 前端靠这个端点决定显示表单还是 SSO 按钮。
func TestAuthConfigByMode(t *testing.T) {
	local := sessionRT(t, Config{Mode: ModeLocal, LocalUsers: []LocalUser{{Username: "ops", PasswordBcrypt: dummyHash()}}})
	oidc := sessionRT(t, Config{Mode: ModeOIDC, OIDC: OIDCConfig{Issuer: "http://idp", ClientID: "c", ProviderName: "安璞 SSO"}})

	body := func(rt *runtime) string {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/auth/config", nil)
		authConfig(rt)(c)
		return w.Body.String()
	}

	if b := body(local); !strings.Contains(b, `"local":true`) || !strings.Contains(b, `"mode":"local"`) {
		t.Fatalf("local 模式响应不符: %s", b)
	}
	b := body(oidc)
	if !strings.Contains(b, "安璞 SSO") || !strings.Contains(b, "/api/auth/oidc/start") {
		t.Fatalf("oidc 模式响应不符: %s", b)
	}
	if strings.Contains(b, "local") {
		t.Fatalf("oidc 模式不应暴露本地登录: %s", b)
	}
}
