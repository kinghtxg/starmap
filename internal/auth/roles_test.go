package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRoleRankAndValidity(t *testing.T) {
	if roleRank(RoleAdmin) <= roleRank(RoleOperator) || roleRank(RoleOperator) <= roleRank(RoleViewer) {
		t.Fatal("角色等级必须严格递增 admin > operator > viewer")
	}
	if roleRank("") != 0 || roleRank("root") != 0 {
		t.Fatal("未知角色等级应为 0（低到不满足任何要求）")
	}
	for _, r := range []string{RoleViewer, RoleOperator, RoleAdmin} {
		if !ValidRole(r) {
			t.Fatalf("%s 应为合法角色", r)
		}
	}
	if ValidRole("superuser") {
		t.Fatal("非法角色不应通过校验")
	}
}

// TestNormalizeRole 归一化只认三个标准值：大小写/空格可以宽容，别名与乱写一律返回空串，
// 由调用方决定回落策略（本地账号回落 operator，OIDC 侧再走别名表）。
// 这样 NormalizeRole 的契约是"严格"，不会把 unknown 悄悄当成 viewer。
func TestNormalizeRole(t *testing.T) {
	cases := map[string]string{
		"admin":      RoleAdmin,
		"ADMIN":      RoleAdmin,
		"  Admin  ":  RoleAdmin,
		"operator":   RoleOperator,
		" Operator ": RoleOperator,
		"viewer":     RoleViewer,
		"VIEWER":     RoleViewer,
		// 未知 / 别名 / 空值：一律空串，不猜
		"":              "",
		"   ":           "",
		"administrator": "",
		"管理员":           "",
		"运维":            "",
		"whatever":      "",
	}
	for in, want := range cases {
		if got := NormalizeRole(in); got != want {
			t.Errorf("NormalizeRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func newRoleCtx(role string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/topology", nil)
	if role != "" {
		c.Set(CtxRole, role)
	}
	return c, rec
}

func TestRequireRoleAllowsAndDenies(t *testing.T) {
	cases := []struct {
		have    string
		want    string
		allowed bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleViewer, RoleAdmin, false},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleViewer, true},
	}
	for _, tc := range cases {
		c, rec := newRoleCtx(tc.have)
		RequireRole(tc.want)(c)
		if got := !c.IsAborted(); got != tc.allowed {
			t.Fatalf("%s 访问 %s 级别：期望放行=%v，实际放行=%v（status=%d）",
				tc.have, tc.want, tc.allowed, got, rec.Code)
		}
		if !tc.allowed && rec.Code != http.StatusForbidden {
			t.Fatalf("拒绝时应返回 403，得到 %d", rec.Code)
		}
	}
}

// TestRequireRoleUnsetDefaultsToAdmin 未启用认证（mode=none）时上下文里没有角色，
// 必须按 admin 处理 —— 这是 K1「零配置可用」的前提，写错会导致默认部署全部 403。
func TestRequireRoleUnsetDefaultsToAdmin(t *testing.T) {
	c, _ := newRoleCtx("")
	if got := Role(c); got != RoleAdmin {
		t.Fatalf("未设置角色时应回落 admin，得到 %q", got)
	}
	RequireRole(RoleAdmin)(c)
	if c.IsAborted() {
		t.Fatal("未启用认证时 admin 级路由不应被拦截")
	}
}

func TestHasRole(t *testing.T) {
	c, _ := newRoleCtx(RoleOperator)
	if !HasRole(c, RoleViewer) {
		t.Fatal("operator 应满足 viewer 级要求")
	}
	if HasRole(c, RoleAdmin) {
		t.Fatal("operator 不应满足 admin 级要求")
	}
}

// TestResolveLocalRoleDefault 本地账号没写 role 时给 operator 而不是 admin：
// 少写一个字段就拿到最高权限，是最典型的"配置疏漏造成越权"。
func TestResolveLocalRoleDefault(t *testing.T) {
	if got := resolveLocalRole(LocalUser{Username: "bob"}); got != defaultLocalRole {
		t.Fatalf("未配置角色应回落 %q，得到 %q", defaultLocalRole, got)
	}
	if got := resolveLocalRole(LocalUser{Username: "cy", Role: RoleAdmin}); got != RoleAdmin {
		t.Fatalf("显式角色被覆盖: %q", got)
	}
	if got := resolveLocalRole(LocalUser{Username: "dd", Role: "乱写"}); !ValidRole(got) {
		t.Fatalf("非法角色应被归一化，得到 %q", got)
	}
}

// TestRoleFromClaims OIDC 侧消费上游角色声明：roles 优先，其次 groups，最后 viewer。
func TestRoleFromClaims(t *testing.T) {
	cases := []struct {
		claims idClaims
		want   string
	}{
		{idClaims{Roles: []string{"admin"}}, RoleAdmin},
		{idClaims{Roles: []string{"operator"}}, RoleOperator},
		{idClaims{Roles: []string{"viewer"}}, RoleViewer},
		{idClaims{Groups: []string{"starmap-admin"}}, RoleAdmin},
		{idClaims{Groups: []string{"运维"}}, RoleOperator},
		{idClaims{Groups: []string{"只读"}}, RoleViewer},
		{idClaims{Roles: []string{"reader"}}, RoleViewer},
		{idClaims{}, RoleViewer}, // 上游什么都没给 → 最小权限
	}
	for _, tc := range cases {
		if got := roleFromClaims(tc.claims); got != tc.want {
			t.Errorf("roleFromClaims(%+v) = %q, want %q", tc.claims, got, tc.want)
		}
	}
}

// TestMergeKeepsDefaults 守住「只写 auth.mode 就把默认值清空」这个坑。
func TestMergeKeepsDefaults(t *testing.T) {
	base := Default()
	merged := Merge(base, Config{
		Mode:       ModeLocal,
		LocalUsers: []LocalUser{{Username: "alice", Password: "pw", Role: RoleViewer}},
	})
	if merged.Mode != ModeLocal {
		t.Fatalf("mode 未合并: %q", merged.Mode)
	}
	if merged.SessionTTLSeconds != base.SessionTTLSeconds {
		t.Fatalf("session_ttl 被清空: %d", merged.SessionTTLSeconds)
	}
	if merged.CookieName != base.CookieName {
		t.Fatalf("cookie_name 被清空: %q", merged.CookieName)
	}
	if len(merged.OIDC.Scopes) == 0 {
		t.Fatal("oidc.scopes 被清空")
	}
	if err := merged.Validate(); err != nil {
		t.Fatalf("合并结果应合法: %v", err)
	}
}

// TestMergeOnlyOverridesGiven 只覆盖显式给出的字段。
func TestMergeOnlyOverridesGiven(t *testing.T) {
	base := Default()
	merged := Merge(base, Config{
		SessionTTLSeconds: 60,
		LocalUsers:        []LocalUser{{Username: "e", Password: "p", Role: RoleViewer}},
		OIDC:              OIDCConfig{Issuer: "https://sso.example.com"},
	})
	if merged.SessionTTLSeconds != 60 {
		t.Fatalf("ttl 未覆盖: %d", merged.SessionTTLSeconds)
	}
	if merged.OIDC.Issuer != "https://sso.example.com" {
		t.Fatalf("issuer 未覆盖: %q", merged.OIDC.Issuer)
	}
	if merged.OIDC.ProviderName != base.OIDC.ProviderName {
		t.Fatalf("provider_name 不应被清空: %q", merged.OIDC.ProviderName)
	}
	if len(merged.LocalUsers) != 1 {
		t.Fatalf("local_users 未合并: %+v", merged.LocalUsers)
	}
}
