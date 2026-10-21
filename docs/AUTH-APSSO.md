# StarMap 星图 V1.1 — 账号系统 + APSSO SSO

> 模块：`internal/auth` · 登录页 `web/login.html` · 部署 `scripts/deploy-apsso.sh`
> 合规依据：`docs/PM-DATA-INGEST-V2-DESIGN.md §7`（PM 已下裁定）
> 状态：**能力已实现，主协调者需按文末「接入指南」完成 4 处接线后生效**

---

## 1. 一句话定位

**可选、可关、只做门卫。** StarMap 不自建账号体系、不建权限管理；需要门卫时，外接 APSSO（OIDC）
回答「谁能打开这个页面」，并把身份写进审计日志的 `Actor`。不需要时，`auth.mode = none`，
系统行为与 1.0.0 **逐字一致**。

> **1.1.0 修订**：门卫从「已认证 / 未认证」两档，扩为**三级粗粒度门禁**
> （`viewer` < `operator` < `admin`）。扩的理由是运维现实：只读账号（值班看板、领导巡览）
> 和有写权限的账号混在一档，等于把"删资产、跑全端口扫描"的按钮摆给所有人。
> 但**角色只区分能不能改，不区分能看什么**，也不引入用户表/权限管理界面/资源级 ACL——
> 这不构成 RBAC 产品能力，见 §6。

### 三条硬约束（实现已逐条遵守）

| # | 约束 | 本模块的实现 |
|---|---|---|
| **K1** | 默认关闭（opt-in） | `auth.mode` 默认 `none`；`Middleware` 在 `none` 下直接 `c.Next()`，不新增任何重定向、不阻断任何请求 |
| **K2** | 不自建账号与权限体系 | 只做三级粗粒度门禁（`viewer`/`operator`/`admin`），**角色由外部身份源声明或配置文件给定**。**无用户表、无用户管理 UI、无资源级 ACL、无数据范围、无审批流**。读接口对所有角色开放，分级只作用于写操作 |
| **K3** | 不影响检测与产出 | 认证只在 HTTP 入口生效；检测、拓扑、事件、告警代码路径完全不读认证状态。同一份数据在开关两种状态下产出一致 |

> 说明：设计文档 §7.5 曾提到 viewer/operator 两档，V1.1 一度收紧为「已认证 / 未认证」单档。
> 1.1.0 恢复为三级，判据是：**门禁是否产生"数据可见性差异"**。当前实现里三个角色看到的
> 数据完全相同，只有写操作入口被收敛——这是防误操作，不是管控。凡是需要"某人只能看某网段"
> 的需求，一律推给上游身份源/数据侧权限，StarMap 不实现。

---

## 2. 三种模式与取舍

| 模式 | 适用场景 | 行为 | 取舍 |
|---|---|---|---|
| `none`（**默认**） | 单机内网、可信网段、反代后置 Basic Auth | 不启用任何认证；`/api/auth/config` 返回 `mode: none` | ✅ 零改动、零风险、与 V1.0 一致；❌ 写接口裸奔（P0-4 的其余护栏仍需自行落地：默认监听 127.0.0.1、CORS 白名单） |
| `local` | 没有 APSSO、或临时部署，需要一个最小门卫 | 账号密码登录，密码 **bcrypt** 存储/校验 | ✅ 零外部依赖；❌ 账号写进配置文件（运维负担），无自助改密、无锁定策略 |
| `oidc` | 实验室/客户已部署 APSSO，希望统一身份与审计可追溯 | 跳转 APSSO，`authorization_code + PKCE(S256) + state` | ✅ 身份统一、审计 Actor 为真人、口令不落 StarMap；❌ 依赖身份服务可达（不可达时返回 503，**绝不静默放行**） |

**切换方式**：改 `config.yaml` 的 `auth.mode` 后重启；或用环境变量 `STARMAP_AUTH_MODE=oidc` 覆盖（优先级高于配置文件）。
一键部署用 `scripts/deploy-apsso.sh`，加 `--no-sso` 即写入 `mode: none`。

---

## 3. 配置说明

### 3.1 `configs/config.yaml`

```yaml
auth:
  mode: "none"              # none | local | oidc，默认 none（K1）
  session_secret: ""        # 会话 Cookie 的 HMAC-SHA256 密钥；留空则每次启动随机生成（重启后需重新登录）
  session_ttl_seconds: 43200
  cookie_name: "starmap_session"
  cookie_secure: false      # 内网 http 部署保持 false；全站 https 改为 true
  cookie_domain: ""
  public_paths: []          # 额外放行的路径前缀，例如被反代暴露的 /api/health

  # mode=local 时生效
  local_users:
    - username: "admin"
      display_name: "系统管理员"
      password_bcrypt: "$2a$10$...."   # 推荐：用 auth.HashPassword() 生成
      # password: "明文"               # 仅一键部署便利，启动时自动 bcrypt 散列化并打印 WARN

  # mode=oidc 时生效（APSSO；全部走配置，代码内无任何真实域名）
  oidc:
    issuer: "https://idp.example.com"
    client_id: "starmap"
    client_secret: ""
    redirect_url: "http://10.0.0.5:8080/api/auth/callback"  # 留空则按访问地址自动推导
    scopes: ["openid", "profile", "email"]
    provider_name: "APSSO"        # 登录按钮文案
    skip_tls_verify: false        # 内网自签证书按需开启，默认关闭
    timeout_seconds: 10
```

### 3.2 环境变量覆盖（一键部署 / 容器友好，优先级高于配置文件）

| 变量 | 作用 |
|---|---|
| `STARMAP_AUTH_MODE` | 覆盖 `auth.mode` |
| `STARMAP_AUTH_SESSION_SECRET` / `STARMAP_SESSION_SECRET` | 会话签名密钥 |
| `STARMAP_AUTH_TTL` | 会话时长（秒） |
| `STARMAP_AUTH_COOKIE_SECURE` | `true`/`1` 时 Cookie 加 `Secure` |
| `STARMAP_AUTH_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URL` | OIDC 四项 |
| `STARMAP_AUTH_SKIP_TLS_VERIFY` | 跳过身份服务证书校验 |

### 3.3 内置放行的路径（无需认证）

`/api/health`、`/login`、`/login.html`、`/api/auth/*`、`/assets/*`、
静态资源后缀（`.js/.css/.png/.ico/.svg/...`）、以及 `auth.public_paths` 中配置的自定义前缀。

---

## 4. HTTP 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/login` | 登录页（内嵌 `web/login.html`，零 CDN） |
| GET | `/api/auth/config` | 返回 `{mode, enabled, ttl, provider_name, oidc_start}`，前端据此渲染表单或 SSO 按钮 |
| POST | `/api/auth/login` | 本地账号登录 `{username,password}` → 成功签发会话 |
| GET | `/api/auth/oidc/start` | 发起 APSSO 登录：生成 `state` + PKCE verifier 后 302 到授权端点 |
| GET | `/api/auth/callback` | APSSO 回调：校验 state → 换令牌 → 校验 ID Token → 签发会话 → 回跳 |
| POST | `/api/auth/logout` | 吊销会话 + 清除 Cookie |
| GET | `/api/auth/me` | 当前身份；未认证返回 401 |

未认证时的表现：**HTML 页面 302 到 `/login?next=<原路径>`；`/api/*` 返回 `401 {"error":"未认证"}`**。

---

## 5. 安全实现要点

- **会话**：`HttpOnly` + `SameSite=Lax` +（可选）`Secure` Cookie；载荷为 JSON，用
  **HMAC-SHA256** 自签名（`payload.signature`），密钥取自 `session_secret` 或环境变量；
  未配置密钥时随机生成并打印 WARN。不引入任何第三方会话库。
- **CSRF**：OIDC 使用 `state`（一次性、HttpOnly Cookie 双写比对，10 分钟有效）+ **PKCE S256**；
  `POST /api/auth/login` 与 `/logout` 校验 `Origin` 与 `Host` 一致；回跳地址 `next` 只接受本站相对路径。
- **口令**：bcrypt（`golang.org/x/crypto/bcrypt`，已在依赖树中，未新增 go.mod 依赖）；
  账号不存在时执行同等开销的 dummy 比对，防用户名枚举。
- **ID Token**：走 APSSO 发现文档的 `jwks_uri` 验签（RS256 / ES256），并校验 `iss`、`aud`、`exp`；
  验签失败**不降级**为「已登录」，也**不降级**为匿名放行。
- **故障 semantics**：身份服务不可达 / 拒绝 → `503` 错误页（见 §7.5「不允许静默放行」）。
- **密钥不回显**：`session_secret`、`client_secret`、本地账号口令字段均标注 `json:"-"`，
  不会被 `GET /api/config` 返回；`PUT /api/config` 也不会改写它们（`mergeRuntimeConfig` 不含 auth）。

---

## 6. 与「不自建账号与权限体系」红线的关系

1. **不自建账号体系**：`mode=oidc` 时用户完全由 APSSO 维护，StarMap 无用户表；`mode=local` 的账号
   只是配置文件里的几条 bcrypt 散列，无增删改 UI、无改密、无锁定、无自助注册。
2. **不做权限管理，只做粗粒度门禁**：三个角色，来源只有两处——外部身份源的 `roles`/`groups`
   声明，或配置文件里的 `local_users[].role`（留空回落 `operator` 并打 WARN）。
   没有第四级，也没有"自定义角色/权限点/授权矩阵"。
3. **门禁只作用于写操作**：所有读接口对 `viewer` 同样开放；被拦的只有
   `PUT /api/config`、`DELETE /api/assets`、`POST /api/ports/scan`、白名单增删、事件复核、
   探针触发这类会改变系统状态或消耗资源的动作。
4. **前端门禁是呈现层收敛，不是权限引擎**：写操作按钮带 `data-role="operator|admin"`，
   由 `html[data-sm-role=...]` 的 CSS 属性选择器隐藏。它同时解决"动态插入的表格行/右键菜单
   漏网"的问题，也让后端成为唯一判定点——**哪怕有人改 DOM 把按钮放出来，请求照样 403**。
5. **登录态不参与业务判定**：检测规则、白名单匹配、复核结论、拓扑计算的逻辑一律不读认证状态。
6. **它提升合规可追溯性**：接入后审计日志 `Actor` 从硬编码 `"api"` 变成真实账号
   （`auth.Subject(c)`），回答了「谁把这个高危事件标成了误报」。角色一并落日志，
   可以回答「谁有权限改，且谁真的改了」。
7. **红线措辞已同步**（1.1.0 完成）：`README.md`、`SPEC.md`、`web/about.html` 的表述统一为
   「**不自建账号与权限体系；可外接身份源（OIDC/APSSO）作为可选门卫，默认关闭；
   门卫只做三级粗粒度写权限收敛，不做数据可见性管控**」。

## 7. 一键部署

```bash
# 接入 APSSO（交互式补齐 issuer/client_id/client_secret）
sudo bash scripts/deploy-apsso.sh \
  --issuer https://idp.example.com \
  --client-id starmap \
  --client-secret 'xxxxxxxx' \
  --redirect-url http://10.0.0.5:8080/api/auth/callback

# 完全不启用 SSO（与 V1.0 行为一致）
sudo bash scripts/deploy-apsso.sh --no-sso

# 本地账号门卫
sudo bash scripts/deploy-apsso.sh --mode local --local-user admin
```

脚本行为：构建/取用二进制 → 安装 `/opt/starmap` → 生成 `/etc/starmap/config.yaml`（**权限 600**，
含随机 `session_secret`）→ 写 systemd unit（含 `ProtectSystem/ProtectHome/PrivateTmp/
AmbientCapabilities=CAP_NET_RAW`）→ 启动 → 健康检查并回显 `/api/auth/config`。
**未填 SSO 参数不会阻塞安装**，只会写入 `auth.mode: none`。

---

## 8. 已知限制（本期明确不做）

- **不做 refresh_token 续期**：会话到期后重新发起一次 SSO（APSSO 侧通常仍有会话，用户基本无感）。
  服务端不保存任何口令或令牌明文。
- **不做用户管理 UI / 改密 / 锁定 / 邀请**（红线 §7.4）。
- **不做登录失败限流**：`mode=local` 建议置于可信网段或反代之后。
- **会话为内存态**：进程重启后已签发会话失效（这是刻意选择——不落库就不落库明文凭据）。
- `mode=none` 时 P0-4 的其余护栏（默认监听 127.0.0.1、CORS 白名单、`Actor=ClientIP`）仍需落地，
  本模块不替代它们。

---

## 9. 接入指南（给主协调者）

> `internal/auth` 只提供能力，**不自行挂载**。请在**被禁止由我修改**的 4 个文件里按下列片段接线。
> 全部改完后：`go build ./...` → 用 `mode=none` 回归一遍现有 E2E（应完全无变化），再切 `local` 自测。

### 9.1 `internal/model/model.go` — `SystemConfig` 新增字段

```go
import (
	"starmap/internal/auth"   // 新增（auth 不反向依赖 model，无循环引用）
)

type SystemConfig struct {
	// ... 既有字段保持不变 ...
	CorsOrigins []string `json:"cors_origins" yaml:"cors_origins"`

	// V1.1 认证（可选，默认关闭）：none | local | oidc，详见 docs/AUTH-APSSO.md
	Auth auth.Config `json:"auth" yaml:"auth"`
}
```

> 密钥字段在 `auth.Config` 内已标 `json:"-"`，`GET /api/config` 不会回显。

### 9.2 `internal/config/config.go` — `Default()` 增加默认值

在 `Default()` 的返回结构体里补一行：

```go
		AuditRetentionDays: 90,
		Auth:               auth.Default(), // auth.mode 默认 none（K1 默认关闭）
```

并在 `Load()` 的合并段末尾补（文件里显式写了 `auth.mode` 才覆盖，否则保留默认）：

```go
	if fileCfg.Auth.Mode != "" {
		cfg.Auth = fileCfg.Auth // 空字段由 auth 包在运行时补默认值
	}
```

### 9.3 `internal/api/server.go` — `NewRouter` 挂载中间件与路由

把现有的：

```go
	// 认证 middleware 接口位（本期不做登录/SSO/RBAC，SPEC §1/§12）
	r.Use(authPlaceholder())
```

替换为（**必须在 `api := r.Group("/api")` 之前**，gin 的全局中间件只对之后注册的路由生效）：

```go
	// 认证 middleware（V1.1）：mode=none 时与 authPlaceholder 等价，直接放行（K1）
	if d.Cfg != nil {
		r.Use(auth.Middleware(d.Cfg.Auth))
		auth.RegisterRoutes(r, d.Cfg.Auth) // /login、/api/auth/*
	}
```

并在 import 块中加入 `"starmap/internal/auth"`。
`auth.RegisterRoutes` 在 `mode=none` 时只注册一个只读的 `/api/auth/config`，不产生任何行为变化。

### 9.4 `cmd/starmap/main.go` — 校验并打印（配置已随 `SystemConfig` 一起加载）

在「1. 配置」之后（`cfg, err := config.Load(*cfgPath)` 的错误处理之后）插入：

```go
	// 1.1 认证配置（默认 none：不引入任何登录要求；非法配置直接拒绝启动）
	if err := cfg.Auth.Validate(); err != nil {
		log.Fatalf("认证配置非法: %v", err)
	}
	if cfg.Auth.Enabled() {
		log.Printf("[auth] 已启用认证: mode=%s ttl=%ds cookie=%s",
			cfg.Auth.Mode, cfg.Auth.SessionTTLSeconds, cfg.Auth.CookieName)
	} else {
		log.Printf("[auth] 未启用认证（mode=none），行为与 V1.0 一致")
	}
```

若需要在 main 中**显式构造**（例如从独立文件或环境变量装配），等价写法：

```go
	authCfg := auth.Default()                 // mode=none
	authCfg.Mode = auth.ModeOIDC              // 或 auth.ModeLocal
	authCfg.OIDC.Issuer = "https://idp.example.com"
	authCfg.OIDC.ClientID = "starmap"
	authCfg.OIDC.ClientSecret = os.Getenv("STARMAP_AUTH_CLIENT_SECRET")
	authCfg.OIDC.RedirectURL = "http://10.0.0.5:8080/api/auth/callback"
	if err := authCfg.Validate(); err != nil {
		log.Fatalf("认证配置非法: %v", err)
	}
	cfg.Auth = authCfg
```

### 9.5 可选（P0-4 相关）：审计 `Actor` 改为真实身份

`server.go` 中硬编码的 `Actor: "api"`（约 12 处）建议改为：

```go
	actor := auth.Subject(c)
	if actor == "" {
		actor = c.ClientIP() // mode=none 时退化为来源 IP（PM 审查 P0-4 建议）
	}
```

### 9.6 注意事项

- `PUT /api/config` 的持久化合并函数 `mergeRuntimeConfig` **不需要**处理 `Auth`：
  认证配置不接受前端热改（避免被远程关闭门卫）。
- 反代（nginx）场景请把 `X-Forwarded-Proto` 透传，`redirect_url` 留空时服务据此推导回调地址。
- `web/login.html` 已被 `web/embed.go` 的 `//go:embed *.html` 覆盖，无需改动 embed。
