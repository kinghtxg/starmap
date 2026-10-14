#!/usr/bin/env bash
# StarMap 星图 V1.0 — Linux 一键部署脚本
# 功能：依赖检测（Go 或预编译二进制）→ 构建 → 安装到 /opt/starmap → 生成 systemd unit → 启动。
# 用法：sudo bash scripts/deploy.sh [--port 8080] [--binary /path/to/starmap]
set -euo pipefail

APP=starmap
PREFIX=/opt/starmap
CONF_DIR=/etc/starmap
PORT=8080
BIN=""
SERVICE_USER="${SUDO_USER:-root}"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --binary) BIN="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "==> 源码目录: $SRC_DIR"

# ---------- 1. 依赖检测与构建 ----------
if [ -n "$BIN" ] && [ -x "$BIN" ]; then
  echo "==> 使用预编译二进制: $BIN"
else
  GO=""
  for g in "$(command -v go || true)" /usr/local/go/bin/go "$HOME/sdk/go/bin/go"; do
    if [ -n "$g" ] && "$g" version >/dev/null 2>&1; then GO="$g"; break; fi
  done
  if [ -z "$GO" ]; then
    echo "==> 未检测到 Go，正在安装 go1.22.12 到 /usr/local/go ..."
    ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64
    [ "$ARCH" = "aarch64" ] && ARCH=arm64
    TARBALL="go1.22.12.linux-${ARCH}.tar.gz"
    curl -sSLO "https://dl.google.com/go/${TARBALL}"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "$TARBALL" && rm -f "$TARBALL"
    GO=/usr/local/go/bin/go
  fi
  echo "==> Go: $($GO version)"
  echo "==> 构建（CGO_ENABLED=0 纯静态）..."
  cd "$SRC_DIR"
  CGO_ENABLED=0 GOFLAGS=-mod=mod GOPROXY="${GOPROXY:-https://goproxy.cn,direct}" \
    "$GO" build -trimpath -ldflags "-s -w" -o /tmp/starmap-build ./cmd/starmap
  BIN=/tmp/starmap-build
fi

# ---------- 2. 安装 ----------
echo "==> 安装到 $PREFIX"
mkdir -p "$PREFIX" "$CONF_DIR"
install -m 0755 "$BIN" "$PREFIX/starmap"

if [ ! -f "$CONF_DIR/config.yaml" ]; then
  cat > "$CONF_DIR/config.yaml" <<EOF
# StarMap 星图配置（详见 configs/config.yaml 注释）
listen_addr: ":${PORT}"
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
EOF
  echo "==> 已生成默认配置 $CONF_DIR/config.yaml"
fi

# ---------- 3. systemd unit ----------
if command -v systemctl >/dev/null 2>&1; then
  echo "==> 生成 systemd unit"
  cat > /etc/systemd/system/starmap.service <<EOF
[Unit]
Description=StarMap 星图 · 网内拓扑自动测绘引擎 V1.0
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

# ---------- 4. 健康检查 ----------
for i in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    echo "==> 部署完成 ✅  访问 http://<本机IP>:${PORT}/"
    exit 0
  fi
  sleep 0.5
done
echo "!! 健康检查超时，请查看日志: journalctl -u starmap 或 $PREFIX/starmap.log" >&2
exit 1
