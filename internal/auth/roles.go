package auth

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 角色。三级足够覆盖"看 / 操作 / 管"的日常分工，不做更细的资源级 ACL。
//
// 与合规裁定 K2 的关系（V1.0 后修订，见 docs/AUTH-APSSO.md）：
// 原裁定是「只做门卫，不实现角色」。实践中发现缺少角色分级会让"只读巡检账号"
// 也具备改配置、删资产的权限，这在政务网等多人共用场景是实打实的风险。
// 因此修订为：**仍不自建用户表与权限体系**，只做两件事——
//  1. 本地账号在配置里标注一个角色（一个字段，不是权限模型）；
//  2. OIDC 模式下从身份源已有的角色声明读取（上游管权限，我们只消费）。
//
// 换句话说：权限的"权威来源"始终在外部（配置文件或身份源），StarMap 不发明权限。
const (
	// RoleViewer 只读：查看拓扑、资产、事件、台账。巡检/审计人员用。
	RoleViewer = "viewer"
	// RoleOperator 操作：在只读之上，可复核事件、维护台账、归档资产、触发探测。
	RoleOperator = "operator"
	// RoleAdmin 管理：在操作之上，可改系统配置、删除资产/域/探针、清空台账。
	RoleAdmin = "admin"
)

// CtxRole gin.Context 中的角色键。
const CtxRole = "auth_role"

// roleRank 角色等级。数字越大权限越高；未知角色按 0 处理（等于无权限）。
func roleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// ValidRole 判断角色名是否合法。
func ValidRole(role string) bool { return roleRank(role) > 0 }

// NormalizeRole 归一化角色名；未知值返回空串（由调用方决定回落策略）。
func NormalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return RoleAdmin
	case RoleOperator:
		return RoleOperator
	case RoleViewer:
		return RoleViewer
	}
	return ""
}

// Role 取出当前请求的角色。未启用认证时返回 admin（K1：零配置即可用）。
func Role(c *gin.Context) string {
	if v, ok := c.Get(CtxRole); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return RoleAdmin
}

// HasRole 判断当前请求是否达到某等级。
func HasRole(c *gin.Context, want string) bool {
	return roleRank(Role(c)) >= roleRank(want)
}

// RequireRole 路由级权限中间件：低于所需等级返回 403。
//
// 为什么在路由层而不是 handler 里判断：一个接口的权限要求应该和它的路径写在一起，
// 才能"看路由表就知道谁能调"。散在 handler 里必然漏。
func RequireRole(want string) gin.HandlerFunc {
	return func(c *gin.Context) {
		got := Role(c)
		if roleRank(got) < roleRank(want) {
			slog.Warn("rbac_denied",
				"path", c.Request.URL.Path,
				"method", c.Request.Method,
				"role", got,
				"required", want,
				"subject", Subject(c),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":    "权限不足",
				"role":     got,
				"required": want,
			})
			return
		}
		c.Next()
	}
}

// defaultLocalRole 本地账号未显式配置角色时的回落值。
//
// 选 operator 而不是 admin：默认给最小必要权限，改配置这类高风险动作必须显式授权。
// 也不选 viewer：否则新装系统的人第一件事就是发现自己啥也改不了，体验很差。
const defaultLocalRole = RoleOperator

// resolveLocalRole 计算本地账号的实际角色，并对"未显式配置"给出启动告警。
func resolveLocalRole(u LocalUser) string {
	if r := NormalizeRole(u.Role); r != "" {
		return r
	}
	slog.Warn("auth_user_without_role",
		"user", u.Username,
		"assumed", defaultLocalRole,
		"hint", "建议在配置中显式指定 role: viewer|operator|admin",
	)
	return defaultLocalRole
}
