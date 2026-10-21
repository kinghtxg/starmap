package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// providerMeta OIDC 发现文档（/.well-known/openid-configuration）的必要字段。
type providerMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// jwkSet / jwk 身份服务的 JWKS 公钥集（仅支持 RS256 与 ES256）。
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// idClaims ID Token Claims。
type idClaims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	Exp               int64           `json:"exp"`
	Name              string          `json:"name"`
	PreferredUsername string          `json:"preferred_username"`
	Email             string          `json:"email"`
	// 角色声明：覆盖 OIDC / APSSO / Keycloak / Azure AD 最常见的两种承载方式。
	// 只认这两种是刻意的——再往上加各种厂商私有字段（realm_access.roles 等）
	// 会把身份源适配问题变成 StarMap 的维护负担。上游只要能映射成 roles 或 groups 即可。
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
}

// roleFromClaims 从身份源声明中解析出 StarMap 角色。
//
// 取值顺序：roles 里第一个能识别的 → groups 里第一个能识别的 → 兜底 viewer。
// **兜底取最小权限**：身份源没配角色时，宁可只读也不默认给写权限。
// 兼容常见写法（管理员/只读等中文与大小写变体），避免为了一个大小写去改身份源配置。
func roleFromClaims(c idClaims) string {
	for _, list := range [][]string{c.Roles, c.Groups} {
		for _, raw := range list {
			if r := NormalizeRole(raw); r != "" {
				return r
			}
			// 常见别名：AD/Keycloak 里多带前缀或中文
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "administrator", "starmap-admin", "管理员", "系统管理员":
				return RoleAdmin
			case "editor", "writer", "starmap-operator", "操作员", "运维":
				return RoleOperator
			case "reader", "readonly", "read-only", "starmap-viewer", "只读", "观察员":
				return RoleViewer
			}
		}
	}
	return RoleViewer
}

func (c idClaims) display() string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	if c.Name != "" {
		return c.Name
	}
	if c.Email != "" {
		return c.Email
	}
	return c.Sub
}

// oidcClient 访问 APSSO（OIDC 身份服务）的客户端。
type oidcClient struct {
	cfg  OIDCConfig
	http *http.Client

	mu     sync.Mutex
	meta   *providerMeta
	keys   *jwkSet
	keysAt time.Time
}

func newOIDCClient(cfg OIDCConfig) *oidcClient {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			// 内网身份服务常为自签证书，由 skip_tls_verify 显式开启（默认关闭）。
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
	}
	return &oidcClient{
		cfg:  cfg,
		http: &http.Client{Transport: tr, Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
	}
}

var errNotConfigured = errors.New("oidc 未配置")

// metadata 获取并缓存发现文档；失败不缓存，允许下次重试。
func (o *oidcClient) metadata(ctx context.Context) (*providerMeta, error) {
	if o.cfg.Issuer == "" {
		return nil, errNotConfigured
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.meta != nil {
		return o.meta, nil
	}
	u := o.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问身份服务失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("身份服务返回 %d", resp.StatusCode)
	}
	var m providerMeta
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("解析发现文档失败: %w", err)
	}
	if m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" {
		return nil, errors.New("发现文档缺少 authorization_endpoint / token_endpoint")
	}
	o.meta = &m
	return o.meta, nil
}

// jwks 获取并缓存 JWKS（1 小时）。
func (o *oidcClient) jwks(ctx context.Context, uri string) (*jwkSet, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.keys != nil && time.Since(o.keysAt) < time.Hour {
		return o.keys, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取 JWKS 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS 返回 %d", resp.StatusCode)
	}
	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("解析 JWKS 失败: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS 为空")
	}
	o.keys, o.keysAt = &set, time.Now()
	return o.keys, nil
}

// authorizeURL 生成跳转地址：authorization_code + PKCE(S256) + state。
func (r *runtime) authorizeURL(ctx context.Context, redirectURI, state, verifier string) (string, error) {
	meta, err := r.oidc.metadata(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", r.cfg.OIDC.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(r.cfg.OIDC.Scopes, " "))
	q.Set("state", state)
	// PKCE：challenge = BASE64URL(SHA256(verifier))
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	return meta.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// tokenResponse 令牌端点返回。
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// exchange 用 code + code_verifier 换取令牌。
func (r *runtime) exchange(ctx context.Context, code, redirectURI, verifier string) (tokenResponse, error) {
	var out tokenResponse
	meta, err := r.oidc.metadata(ctx)
	if err != nil {
		return out, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", r.cfg.OIDC.ClientID)
	form.Set("code_verifier", verifier)
	if r.cfg.OIDC.ClientSecret != "" {
		form.Set("client_secret", r.cfg.OIDC.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := r.oidc.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("令牌交换失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("令牌端点返回 %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("解析令牌响应失败: %w", err)
	}
	if out.Error != "" {
		return out, fmt.Errorf("令牌端点返回错误: %s %s", out.Error, out.ErrorDesc)
	}
	return out, nil
}

// identify 从 ID Token（优先）或 userinfo 端点解析身份。
// APSSO 不可达时返回错误 —— 不允许静默放行（防「故障即裸奔」）。
func (r *runtime) identify(ctx context.Context, tok tokenResponse) (idClaims, error) {
	if tok.IDToken != "" {
		claims, err := r.verifyIDToken(ctx, tok.IDToken)
		if err == nil {
			return claims, nil
		}
		// ID Token 校验失败不再降级：避免接受未验签的身份。
		return idClaims{}, err
	}
	return r.userinfo(ctx, tok.AccessToken)
}

func (r *runtime) userinfo(ctx context.Context, accessToken string) (idClaims, error) {
	meta, err := r.oidc.metadata(ctx)
	if err != nil {
		return idClaims{}, err
	}
	if meta.UserInfoEndpoint == "" || accessToken == "" {
		return idClaims{}, errors.New("身份服务未返回 id_token，且无 userinfo 端点")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.UserInfoEndpoint, nil)
	if err != nil {
		return idClaims{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := r.oidc.http.Do(req)
	if err != nil {
		return idClaims{}, fmt.Errorf("访问 userinfo 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return idClaims{}, fmt.Errorf("userinfo 返回 %d", resp.StatusCode)
	}
	var c idClaims
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return idClaims{}, fmt.Errorf("解析 userinfo 失败: %w", err)
	}
	if c.Sub == "" {
		return idClaims{}, errors.New("userinfo 缺少 sub")
	}
	return c, nil
}

// verifyIDToken 校验 ID Token 签名（RS256/ES256，公钥取自 JWKS）与 iss/aud/exp。
func (r *runtime) verifyIDToken(ctx context.Context, idToken string) (idClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return idClaims{}, errors.New("id_token 格式非法")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return idClaims{}, errors.New("id_token 头部解码失败")
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return idClaims{}, errors.New("id_token 头部解析失败")
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return idClaims{}, fmt.Errorf("不支持的签名算法: %s", hdr.Alg)
	}
	meta, err := r.oidc.metadata(ctx)
	if err != nil {
		return idClaims{}, err
	}
	if meta.JWKSURI == "" {
		return idClaims{}, errors.New("发现文档缺少 jwks_uri")
	}
	set, err := r.oidc.jwks(ctx, meta.JWKSURI)
	if err != nil {
		return idClaims{}, err
	}
	key, ok := pickKey(set, hdr.Kid)
	if !ok {
		return idClaims{}, fmt.Errorf("JWKS 中没有 kid=%s 的密钥", hdr.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return idClaims{}, errors.New("id_token 签名解码失败")
	}
	signing := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signing))
	switch hdr.Alg {
	case "RS256":
		pub, err := rsaPublicKey(key)
		if err != nil {
			return idClaims{}, err
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return idClaims{}, errors.New("id_token 签名校验失败")
		}
	case "ES256":
		pub, err := ecPublicKey(key)
		if err != nil {
			return idClaims{}, err
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return idClaims{}, errors.New("id_token 签名校验失败")
		}
	}

	var claims idClaims
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, errors.New("id_token 载荷解码失败")
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return idClaims{}, errors.New("id_token 载荷解析失败")
	}
	if claims.Sub == "" {
		return idClaims{}, errors.New("id_token 缺少 sub")
	}
	if claims.Exp > 0 && claims.Exp < time.Now().Unix() {
		return idClaims{}, errors.New("id_token 已过期")
	}
	if iss := r.cfg.OIDC.Issuer; iss != "" && claims.Iss != "" && !strings.EqualFold(strings.TrimRight(claims.Iss, "/"), iss) {
		return idClaims{}, errors.New("id_token 签发者与配置不一致")
	}
	if !audMatches(claims.Aud, r.cfg.OIDC.ClientID) {
		return idClaims{}, errors.New("id_token 受众与 client_id 不一致")
	}
	return claims, nil
}

func audMatches(raw json.RawMessage, clientID string) bool {
	if len(raw) == 0 || clientID == "" {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return subtle.ConstantTimeCompare([]byte(s), []byte(clientID)) == 1
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, v := range list {
			if subtle.ConstantTimeCompare([]byte(v), []byte(clientID)) == 1 {
				return true
			}
		}
	}
	return false
}

func pickKey(set *jwkSet, kid string) (jwk, bool) {
	if len(set.Keys) == 1 && kid == "" {
		return set.Keys[0], true
	}
	for _, k := range set.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return jwk{}, false
}

func rsaPublicKey(k jwk) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("JWK n 解码失败")
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, errors.New("JWK e 解码失败")
	}
	ei := 0
	for _, b := range e {
		ei = ei<<8 | int(b)
	}
	if ei == 0 || len(n) == 0 {
		return nil, errors.New("JWK 参数非法")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ei}, nil
}

func ecPublicKey(k jwk) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.New("JWK x 解码失败")
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, errors.New("JWK y 解码失败")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
