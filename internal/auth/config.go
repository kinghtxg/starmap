// Package auth 实现 StarMap「可选的账号系统与 APSSO（OIDC）单点登录门卫」。
//
// 合规裁定（见 docs/AUTH-APSSO.md 与 docs/PM-DATA-INGEST-V2-DESIGN.md §7）：
//
//	K1 默认关闭：auth.mode 默认 none，行为与未启用完全一致，不引入任何登录要求；
//	K2 只做门卫：仅「已认证 / 未认证」两种状态，不实现角色、不实现 RBAC、不做权限分级；
//	K3 不影响检测：检测、拓扑、事件、告警逻辑不因鉴权开关发生任何改变。
//
// 本包不建用户表、不做权限模型，只回答「谁能打开这个页面」，并把身份写入
// gin.Context（键 auth.CtxSubject）供审计日志 Actor 使用。
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// 认证模式。
const (
	ModeNone  = "none"  // 默认：完全不启用（K1）
	ModeLocal = "local" // 本地账号（bcrypt）
	ModeOIDC  = "oidc"  // 外部 OIDC 身份源（APSSO）
)

// gin.Context 键名。审计日志 Actor 取 CtxSubject，展示名取 CtxDisplayName。
const (
	CtxSubject     = "auth_subject"
	CtxDisplayName = "auth_display_name"
)

// 默认值与内部常量。
const (
	DefaultCookieName   = "starmap_session"
	DefaultSessionTTL   = 12 * 60 * 60 // 12 小时
	DefaultProviderName = "APSSO"
	DefaultTimeoutSec   = 10 // 访问身份服务的超时（秒）

	stateCookieName = "starmap_auth_state" // OIDC state（CSRF 防护）
	stateCookieTTL  = 10 * 60              // state 有效期 10 分钟
	returnToParam   = "next"               // 登录成功后回跳参数名
)

// LocalUser 本地账号配置（mode=local）。
// PasswordBcrypt 为 bcrypt 散列；Password 为明文，仅在加载时散列化一次，
// 用于一键部署场景（脚本无法自行生成 bcrypt），启动时打印 WARN。
type LocalUser struct {
	Username       string `json:"username" yaml:"username"`
	DisplayName    string `json:"display_name" yaml:"display_name"`
	PasswordBcrypt string `json:"-" yaml:"password_bcrypt"`
	Password       string `json:"-" yaml:"password"`
}

// OIDCConfig 外部 OIDC 身份源配置（APSSO）。
// 全部留空即视为未启用；issuer / client_id / client_secret / redirect_url 一律走配置，
// 代码中不内置任何真实域名。
type OIDCConfig struct {
	Issuer         string   `json:"issuer" yaml:"issuer"`
	ClientID       string   `json:"client_id" yaml:"client_id"`
	ClientSecret   string   `json:"-" yaml:"client_secret"`
	RedirectURL    string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes         []string `json:"scopes" yaml:"scopes"`
	ProviderName   string   `json:"provider_name" yaml:"provider_name"`
	SkipTLSVerify  bool     `json:"skip_tls_verify" yaml:"skip_tls_verify"` // 内网自签证书场景
	TimeoutSeconds int      `json:"timeout_seconds" yaml:"timeout_seconds"` // 0 → DefaultTimeoutSec
}

// Config 认证配置。可直接作为 model.SystemConfig 的 `auth` 字段嵌入。
// 注意：含密钥的字段均标注 json:"-"，不会被 GET /api/config 回显。
type Config struct {
	Mode string `json:"mode" yaml:"mode"` // none | local | oidc，默认 none

	SessionSecret     string `json:"-" yaml:"session_secret"` // HMAC-SHA256 签名密钥
	SessionTTLSeconds int    `json:"session_ttl_seconds" yaml:"session_ttl_seconds"`
	CookieName        string `json:"cookie_name" yaml:"cookie_name"`
	CookieSecure      bool   `json:"cookie_secure" yaml:"cookie_secure"` // 内网 http 保持 false
	CookieDomain      string `json:"cookie_domain" yaml:"cookie_domain"`

	// PublicPaths 额外放行的路径前缀（例如被反代暴露的健康检查）。
	PublicPaths []string    `json:"public_paths" yaml:"public_paths"`
	LocalUsers  []LocalUser `json:"-" yaml:"local_users"`
	OIDC        OIDCConfig  `json:"oidc" yaml:"oidc"`
}

// Default 返回默认配置：mode=none，即完全不启用（K1）。
func Default() Config {
	return Config{
		Mode:              ModeNone,
		SessionTTLSeconds: DefaultSessionTTL,
		CookieName:        DefaultCookieName,
		OIDC: OIDCConfig{
			ProviderName:   DefaultProviderName,
			Scopes:         []string{"openid", "profile", "email"},
			TimeoutSeconds: DefaultTimeoutSec,
		},
	}
}

// Enabled 返回是否启用了认证（mode != none）。
func (c Config) Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case ModeLocal, ModeOIDC:
		return true
	}
	return false
}

// Validate 校验配置合法性；合法返回 nil。
// 未启用（none/空）永远合法 —— 保证「不配置也能一键部署」。
func (c Config) Validate() error {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "", ModeNone:
		return nil
	case ModeLocal:
		n := 0
		for _, u := range c.LocalUsers {
			if u.Username != "" && (u.PasswordBcrypt != "" || u.Password != "") {
				n++
			}
		}
		if n == 0 {
			return fmt.Errorf("auth.mode=local 至少需要配置一个可用账号（username + password_bcrypt）")
		}
		return nil
	case ModeOIDC:
		if strings.TrimSpace(c.OIDC.Issuer) == "" {
			return fmt.Errorf("auth.mode=oidc 需要配置 oidc.issuer")
		}
		if strings.TrimSpace(c.OIDC.ClientID) == "" {
			return fmt.Errorf("auth.mode=oidc 需要配置 oidc.client_id")
		}
		return nil
	default:
		return fmt.Errorf("未知的 auth.mode: %q（可选 none|local|oidc）", c.Mode)
	}
}

// normalized 返回填充默认值、应用环境变量覆盖后的副本。
// 会话密钥为空时生成随机密钥（重启后会话失效，打印 WARN）。
func (c Config) normalized() Config {
	c.applyEnv()
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = ModeNone
	}
	if c.SessionTTLSeconds <= 0 {
		c.SessionTTLSeconds = DefaultSessionTTL
	}
	if strings.TrimSpace(c.CookieName) == "" {
		c.CookieName = DefaultCookieName
	}
	if c.SessionSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Printf("[auth] 生成随机会话密钥失败: %v", err)
		}
		c.SessionSecret = hex.EncodeToString(b)
		log.Printf("[auth] 未配置 session_secret，已生成随机密钥；进程重启后已签发会话将全部失效")
	}
	if strings.TrimSpace(c.OIDC.ProviderName) == "" {
		c.OIDC.ProviderName = DefaultProviderName
	}
	c.OIDC.Issuer = strings.TrimRight(strings.TrimSpace(c.OIDC.Issuer), "/")
	if c.OIDC.TimeoutSeconds <= 0 {
		c.OIDC.TimeoutSeconds = DefaultTimeoutSec
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "profile", "email"}
	}
	// 明文密码只在加载期散列化一次，之后不保留明文。
	for i := range c.LocalUsers {
		u := &c.LocalUsers[i]
		u.Username = strings.TrimSpace(u.Username)
		if u.PasswordBcrypt != "" || u.Username == "" {
			continue
		}
		if u.Password != "" {
			h, err := HashPassword(u.Password)
			if err != nil {
				log.Printf("[auth] 账号 %s 密码散列失败，已跳过: %v", u.Username, err)
				u.Password = ""
				continue
			}
			u.PasswordBcrypt = h
			log.Printf("[auth] 警告：账号 %s 使用配置文件中的明文密码，请尽快改用 password_bcrypt", u.Username)
		}
		u.Password = ""
	}
	return c
}

// applyEnv 应用环境变量覆盖（一键部署友好，优先级高于配置文件）。
func (c *Config) applyEnv() {
	if v := os.Getenv("STARMAP_AUTH_MODE"); v != "" {
		c.Mode = v
	}
	if v := os.Getenv("STARMAP_AUTH_SESSION_SECRET"); v != "" {
		c.SessionSecret = v
	}
	if v := os.Getenv("STARMAP_SESSION_SECRET"); v != "" && c.SessionSecret == "" {
		c.SessionSecret = v
	}
	if v := os.Getenv("STARMAP_AUTH_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.SessionTTLSeconds = n
		}
	}
	if v := os.Getenv("STARMAP_AUTH_COOKIE_SECURE"); v != "" {
		c.CookieSecure = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("STARMAP_AUTH_ISSUER"); v != "" {
		c.OIDC.Issuer = v
	}
	if v := os.Getenv("STARMAP_AUTH_CLIENT_ID"); v != "" {
		c.OIDC.ClientID = v
	}
	if v := os.Getenv("STARMAP_AUTH_CLIENT_SECRET"); v != "" {
		c.OIDC.ClientSecret = v
	}
	if v := os.Getenv("STARMAP_AUTH_REDIRECT_URL"); v != "" {
		c.OIDC.RedirectURL = v
	}
	if v := os.Getenv("STARMAP_AUTH_SKIP_TLS_VERIFY"); v != "" {
		c.OIDC.SkipTLSVerify = strings.EqualFold(v, "true") || v == "1"
	}
}

// HashPassword 生成 bcrypt 散列（供部署脚本/运维生成 password_bcrypt）。
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
