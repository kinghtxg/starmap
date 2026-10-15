#!/usr/bin/env bash
# StarMap 星图 V1.1 — APSSO(SSO) 一键部署脚本
#
# 定位：SSO 是「可选」的。默认会引导配置 APSSO；加 --no-sso 则写入 auth.mode: none，
#       与 V1.0 行为完全一致（不引入任何登录要求）。本地账号模式（--mode local）用于
#       没有 APSSO 但需要门卫的场景。
#
# 用法：
#   sudo bash scripts/deploy-apsso.sh \
#     --issuer https://idp.example.com --client-id starmap --client-secret 'xxxx' \
#     [--redirect-url http://10.0.0.5:8080/api/auth/callback] [--port 8080]
#
#   sudo bash scripts/deploy-apsso.sh --no-sso                 # 不启用 SSO（默认行为）
#   sudo bash scripts/deploy-apsso.sh --mode local --local-user admin
#
# 全部参数也可用环境变量传入（非交互 CI 场景）：
#   SSO_ISSUER / SSO_CLIENT_ID / SSO_CLIENT_SECRET / SSO_REDIRECT / SSO_SKIP_TLS_VERIFY
#
# 详见 docs/AUTH-APSSO.md
set -euo pipefail

APP=starmap
PREFIX="${PREFIX:-/opt/starmap}"
CONF_DIR="${CONF_DIR:-/etc/starmap}"
PORT="${PORT:-8080}"
LISTEN="${LISTEN:-127.0.0.1}"
BIN="${BIN:-}"
MODE="${MODE:-}"                 # none | local | oidc；空=交互选择
ISSUER="${SSO_ISSUER:-}"
CLIENT_ID="${SSO_CLIENT_ID:-}"
CLIENT_SECRET="${SSO_CLIENT_SECRET:-}"
REDIRECT_URL="${SSO_REDIRECT:-}"
SKIP_TLS="${SSO_SKIP_TLS_VERIFY:-false}"
LOCAL_USER="${LOCAL_USER:-}"
LOCAL_PASS="${LOCAL_PASS:-}"
PROVIDER_NAME="${PROVIDER_NAME:-APSSO}"
NO_SSO=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-sso)        NO_SSO=1; MODE=none; shift ;;
    --mode)          MODE="$2"; shift 2 ;;
    --issuer)        ISSUER="$2"; shift 2 ;;
    --client-id)     CLIENT_ID="$2"; shift 2 ;;
    --client-secret) CLIENT_SECRET="$2"; shift 2 ;;
    --redirect-url)  REDIRECT_URL="$2"; shift 2 ;;
    --skip-tls-verify) SKIP_TLS=true; shift ;;
    --provider-name) PROVIDER_NAME="$2"; shift 2 ;;
    --local-user)    LOCAL_USER="$2"; shift 2 ;;
    --local-password) LOCAL_PASS="$2"; shift 2 ;;
    --port)          PORT="$2"; shift 2 ;;
    --listen)        LISTEN="$2"; shift 2 ;;
    --prefix)        PREFIX="$2"; shift 2 ;;
    --conf-dir)      CONF_DIR="$2"; shift 2 ;;
    --binary)        BIN="$2"; shift 2 ;;
    -h|--help)       sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "未知参数: $1（--help 查看用法）"; exit 1 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_USER="${SUDO_USER:-root}"
echo "==> 源码目录: $SRC_DIR"

# ---------- 1. 选择认证模式 ----------
if [ -z "$MODE" ]; then
  if [ "$NO_SSO" = "1" ]; then
    MODE=none
  elif [ -t 0 ]; then
    echo
    echo "请选择认证模式："
    echo "  1) oidc  —— 接入 APSSO 单点登录（推荐，需提供 issuer/client_id/client_secret）"
    echo "  2) local —— 本地账号（bcrypt），不依赖身份服务"
    echo "  3) none  —— 不启用登录（与 V1.0 完全一致）"
    read -r -p "输入序号 [1/2/3，默认 3]: " pick
    case "${pick:-3}" in
      1) MODE=oidc ;;
      2) MODE=local ;;
      *) MODE=none ;;
    esac
  else
    MODE=none
    echo "==> 非交互环境且未指定 --mode，默认 auth.mode=none（不启用登录）"
  fi
fi

if [ "$MODE" = "oidc" ] && [ -t 0 ]; then
  [ -z "$ISSUER" ]        && read -r -p "APSSO issuer (例 https://idp.example.com): " ISSUER
  [ -z "$CLIENT_ID" ]     && read -r -p "client_id: " CLIENT_ID
  [ -z "$CLIENT_SECRET" ] && read -r -s -p "client_secret: " CLIENT_SECRET && echo
  [ -z "$REDIRECT_URL" ]  && read -r -p "redirect_url (留空则由服务按访问地址自动推导): " REDIRECT_URL || true
fi

case "$MODE" in
  none|local|oidc) ;;
  *) echo "!! --mode 只支持 none|local|oidc，当前: $MODE" >&2; exit 1 ;;
esac

if [ "$MODE" = "oidc" ]; then
  if [ -z "$ISSUER" ] || [ -z "$CLIENT_ID" ]; then
    echo "!! mode=oidc 必须提供 --issuer 与 --client-id（或设置 SSO_ISSUER / SSO_CLIENT_ID）" >&2
    exit 1
  fi
fi
if [ "$MODE" = "local" ]; then
  if [ -z "$LOCAL_USER" ]; then
    echo "!! mode=local 必须提供 --local-user" >&2; exit 1
  fi
  if [ -z "$LOCAL_PASS" ]; then
    LOCAL_PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"
    echo "==> 已为账号 $LOCAL_USER 生成随机初始密码: $LOCAL_PASS"
    echo "    （明文写入配置，启动时自动 bcrypt 散列化；请首次登录后立即修改）"
  fi
fi

# ---------- 2. 构建 / 取用二进制 ----------
if [ -n "$BIN" ] && [ -x "$BIN" ]; then
  echo "==> 使用预编译二进制: $BIN"
else
  GO=""
  for g in "$(command -v go || true)" /usr/local/go/bin/go "$HOME/sdk/go/bin/go"; do
    if [ -n "$g" ] && "$g" version >/dev/null 2>&1; then GO="$g"; break; fi
  done
  if [ -z "$GO" ]; then
    echo "!! 未检测到 Go，且未提供 --binary。请先安装 Go 或指定预编译二进制。" >&2
    exit 1
  fi
  echo "==> 构建（CGO_ENABLED=0 纯静态）..."
  cd "$SRC_DIR"
  CGO_ENABLED=0 GOFLAGS=-mod=mod GOPROXY="${GOPROXY:-https://goproxy.cn,direct}" \
    "$GO" build -trimpath -ldflags "-s -w" -o /tmp/starmap-build ./cmd/starmap
  BIN=/tmp/starmap-build
fi

# ---------- 3. 安装 ----------
echo "==> 安装到 $PREFIX"
mkdir -p "$PREFIX" "$CONF_DIR"
install -m 0755 "$BIN" "$PREFIX/starmap"

SESSION_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
[ -n "$SESSION_SECRET" ] || SESSION_SECRET="$(date +%s | sha256sum | cut -c1-64)"

# redirect_url 未填时留空：由服务按访问地址自动推导（http(s)://<host>/api/auth/callback）
REDIRECT_LINE=""
[ -n "$REDIRECT_URL" ] && REDIRECT_LINE="    redirect_url: \"${REDIRECT_URL}\""

{
  cat <<EOF
# StarMap 星图配置（由 scripts/deploy-apsso.sh 生成）
# 认证模式：${MODE}   —— 详见 docs/AUTH-APSSO.md
listen_addr: "${LISTEN}:${PORT}"
db_path: "${PREFIX}/starmap.db"
probe_enabled: false
capture_enabled: false      # 实时抓包需 -tags pcap 构建 + libpcap
capture_interfaces: []
aging_seconds: 86400
aggregate_threshold: 20
reverse_proxy_hosts: 10
long_conn_seconds: 3600
heartbeat_max_bytes: 64
audit_retention_days: 90
probe_token: ""             # 生产环境建议设置
cors_origins: []            # 空 = 仅同源

auth:
  mode: "${MODE}"           # none | local | oidc（默认 none：不引入任何登录要求）
  session_secret: "${SESSION_SECRET}"
  session_ttl_seconds: 43200
  cookie_name: "starmap_session"
  cookie_secure: false      # 内网 http 部署保持 false；全站 https 时改为 true
  public_paths: []
EOF

  if [ "$MODE" = "oidc" ]; then
    cat <<EOF
  oidc:
    issuer: "${ISSUER}"
    client_id: "${CLIENT_ID}"
    client_secret: "${CLIENT_SECRET}"
${REDIRECT_LINE}
    scopes: ["openid", "profile", "email"]
    provider_name: "${PROVIDER_NAME}"
    skip_tls_verify: ${SKIP_TLS}   # 内网自签证书场景按需开启
    timeout_seconds: 10
EOF
  fi

  if [ "$MODE" = "local" ]; then
    cat <<EOF
  local_users:
    - username: "${LOCAL_USER}"
      password: "${LOCAL_PASS}"    # 明文，启动时自动 bcrypt 散列化；建议改用 password_bcrypt
EOF
  fi
} > "$CONF_DIR/config.yaml"
chmod 0600 "$CONF_DIR/config.yaml"   # 含 client_secret / session_secret
echo "==> 已写入配置 $CONF_DIR/config.yaml（权限 600）"

if [ "$MODE" != "none" ]; then
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$PREFIX" 2>/dev/null || true
fi

# ---------- 4. 拉起服务 ----------
if command -v systemctl >/dev/null 2>&1; then
  echo "==> 生成 systemd unit"
  cat > /etc/systemd/system/starmap.service <<EOF
[Unit]
Description=StarMap 星图 · 网内拓扑自动测绘引擎（auth.mode=${MODE}）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${PREFIX}
ExecStart=${PREFIX}/starmap -config ${CONF_DIR}/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now starmap
  sleep 1
  systemctl --no-pager --full status starmap | head -5 || true
else
  echo "==> 无 systemd，直接后台启动"
  nohup "$PREFIX/starmap" -config "$CONF_DIR/config.yaml" >"$PREFIX/starmap.log" 2>&1 &
fi

# ---------- 5. 健康检查 ----------
for _ in $(seq 1 24); do
  if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    echo "==> 部署完成 ✅  auth.mode=${MODE}"
    curl -sf "http://127.0.0.1:${PORT}/api/auth/config" | sed 's/^/    /' || true
    echo
    case "$MODE" in
      none)  echo "    未启用登录，访问 http://<本机IP>:${PORT}/ 即可（行为与 V1.0 一致）" ;;
      oidc)  echo "    请在 APSSO 侧注册回调地址: ${REDIRECT_URL:-http://<本机IP>:${PORT}/api/auth/callback}"
             echo "    访问 http://<本机IP>:${PORT}/login 使用 ${PROVIDER_NAME} 登录" ;;
      local) echo "    访问 http://<本机IP>:${PORT}/login 使用 ${LOCAL_USER} 登录" ;;
    esac
    exit 0
  fi
  sleep 0.5
done
echo "!! 健康检查超时，请查看日志: journalctl -u starmap 或 $PREFIX/starmap.log" >&2
exit 1
