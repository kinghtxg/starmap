package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// sessionClaims 会话 Cookie 的载荷。Cookie 使用 HMAC-SHA256 自签名，
// 不引入任何第三方会话库（内网部署、无外部依赖）。
type sessionClaims struct {
	Sub  string `json:"sub"`  // 身份唯一标识（OIDC 为 sub，本地为 username）
	Name string `json:"name"` // 展示名（审计日志 Actor 可读化）
	Role string `json:"role"` // 角色（viewer/operator/admin），见 roles.go
	Via  string `json:"via"`  // local | oidc
	Sid  string `json:"sid"`  // 会话 ID，用于服务端吊销
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func (c *sessionClaims) valid() bool {
	return c.Sub != "" && c.Exp > time.Now().Unix()
}

// sign 生成 "payload.signature" 形式的 Cookie 值。
func (r *runtime) sign(claims sessionClaims) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(r.cfg.SessionSecret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

// verify 校验签名与有效期。
func (r *runtime) verify(value string) (sessionClaims, bool) {
	var claims sessionClaims
	dot := -1
	for i := 0; i < len(value); i++ {
		if value[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(value)-1 {
		return claims, false
	}
	payload, sig := value[:dot], value[dot+1:]
	mac := hmac.New(sha256.New, []byte(r.cfg.SessionSecret))
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return claims, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims, false
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, false
	}
	if !claims.valid() {
		return claims, false
	}
	return claims, true
}

// issue 签发会话并写入 Cookie（HttpOnly + SameSite=Lax）。
//
// 角色随会话一起签名进 Cookie：这样权限判定不需要每次请求回查配置或身份源，
// 且 Cookie 被篡改会因 HMAC 校验失败而整体失效——角色无法被客户端伪造提升。
func (r *runtime) issue(c *gin.Context, sub, name, role, via string) error {
	ttl := time.Duration(r.cfg.SessionTTLSeconds) * time.Second
	now := time.Now()
	sid := randomHex(16)
	claims := sessionClaims{
		Sub:  sub,
		Name: name,
		Role: NormalizeRole(role),
		Via:  via,
		Sid:  sid,
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	}
	if name == "" {
		claims.Name = sub
	}
	value, err := r.sign(claims)
	if err != nil {
		return err
	}
	r.sessions.put(&sessionRecord{
		Sid:      sid,
		Sub:      sub,
		Name:     claims.Name,
		Via:      via,
		Expiry:   now.Add(ttl),
		IssuedAt: now,
	})
	setCookie(c.Writer, &http.Cookie{
		Name:     r.cfg.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   r.cfg.CookieDomain,
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   r.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// revoke 吊销会话并清除 Cookie。
func (r *runtime) revoke(c *gin.Context) {
	if v, err := c.Cookie(r.cfg.CookieName); err == nil && v != "" {
		if claims, ok := r.verify(v); ok && claims.Sid != "" {
			r.sessions.revoke(claims.Sid)
		}
	}
	setCookie(c.Writer, &http.Cookie{
		Name:     r.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   r.cfg.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// sessionFromRequest 从请求中解析有效会话。
func (r *runtime) sessionFromRequest(c *gin.Context) (sessionClaims, bool) {
	v, err := c.Cookie(r.cfg.CookieName)
	if err != nil || v == "" {
		return sessionClaims{}, false
	}
	claims, ok := r.verify(v)
	if !ok {
		return sessionClaims{}, false
	}
	if claims.Sid != "" && r.sessions.revoked(claims.Sid) {
		return sessionClaims{}, false
	}
	return claims, true
}

func setCookie(w http.ResponseWriter, ck *http.Cookie) {
	http.SetCookie(w, ck)
}

// Subject 取出写入 gin.Context 的认证身份；未认证或未启用返回空串。
// 审计日志建议：actor := auth.Subject(c); if actor == "" { actor = c.ClientIP() }
func Subject(c *gin.Context) string {
	if v, ok := c.Get(CtxSubject); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// DisplayName 取出认证身份的展示名。
func DisplayName(c *gin.Context) string {
	if v, ok := c.Get(CtxDisplayName); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
