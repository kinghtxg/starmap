package config

import (
	"os"
	"path/filepath"
	"testing"

	"starmap/internal/auth"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写入临时配置失败: %v", err)
	}
	return p
}

// TestLoadAuthMerged 守住一个曾经真实发生的「静默失效」bug：
// config.yaml 里写了 auth.mode: local，但 Load 从来没有把 fileCfg.Auth 合并进结果，
// 服务照旧以 mode=none 启动——开关写了等于没写，且不报错。
func TestLoadAuthMerged(t *testing.T) {
	path := writeTemp(t, `
auth:
  mode: "local"
  session_ttl_seconds: 7200
  local_users:
    - username: "alice"
      display_name: "Alice"
      role: "viewer"
      password: "secret"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Mode != auth.ModeLocal {
		t.Fatalf("auth.mode 未生效，得到 %q", cfg.Auth.Mode)
	}
	if !cfg.Auth.Enabled() {
		t.Fatal("auth.Enabled() 应为 true")
	}
	if cfg.Auth.SessionTTLSeconds != 7200 {
		t.Fatalf("session_ttl_seconds 未生效: %d", cfg.Auth.SessionTTLSeconds)
	}
	if len(cfg.Auth.LocalUsers) != 1 || cfg.Auth.LocalUsers[0].Username != "alice" {
		t.Fatalf("local_users 未生效: %+v", cfg.Auth.LocalUsers)
	}
	// 文件没写的字段必须保持默认，不能被整段覆盖清空
	if cfg.Auth.CookieName != auth.DefaultCookieName {
		t.Fatalf("cookie_name 被清空: %q", cfg.Auth.CookieName)
	}
	if cfg.Auth.OIDC.ProviderName != auth.DefaultProviderName {
		t.Fatalf("oidc.provider_name 被清空: %q", cfg.Auth.OIDC.ProviderName)
	}
	if len(cfg.Auth.OIDC.Scopes) == 0 {
		t.Fatal("oidc.scopes 被清空")
	}
	if err := cfg.Auth.Validate(); err != nil {
		t.Fatalf("合并后的认证配置应合法: %v", err)
	}
}

// TestLoadAuthAbsentKeepsDefault 不写 auth 段时不得改变默认（mode=none，K1 零配置可用）。
func TestLoadAuthAbsentKeepsDefault(t *testing.T) {
	cfg, err := Load(writeTemp(t, "listen_addr: \"127.0.0.1:9999\"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Mode != auth.ModeNone {
		t.Fatalf("未配置 auth 时应为 none，得到 %q", cfg.Auth.Mode)
	}
	if cfg.Auth.Enabled() {
		t.Fatal("未配置 auth 时不应启用认证")
	}
}

// TestLoadObservability 日志/指标默认值与显式关闭。
func TestLoadObservability(t *testing.T) {
	cfg, err := Load(writeTemp(t, "log_level: \"debug\"\nlog_format: \"json\"\nmetrics_enabled: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "debug" || cfg.LogFormat != "json" {
		t.Fatalf("日志字段未生效: %q %q", cfg.LogLevel, cfg.LogFormat)
	}
	// metrics 默认 true，必须能被显式 false 关掉（这需要一个"是否写过该键"的判断）
	if cfg.MetricsEnabled {
		t.Fatal("metrics_enabled: false 未生效")
	}

	def, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if def.LogLevel != "info" || def.LogFormat != "text" {
		t.Fatalf("日志默认值不对: %q %q", def.LogLevel, def.LogFormat)
	}
	if !def.MetricsEnabled {
		t.Fatal("metrics_enabled 默认应为 true")
	}
}
