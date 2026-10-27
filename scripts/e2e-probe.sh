#!/usr/bin/env bash
# 探针端到端验收：同一份 pcap，走"探针上报"和"直接上传"两条路，
# 落在两个干净实例上，事件矩阵必须一致。
#
# 这个对比是探针唯一的硬验收：探针内部的会话聚合、上报编码、服务端反解
# 任何一环丢字段（SNI/JA3/XFF），对应规则就不会触发，而两侧日志都是正常的。
# 只测"探针能跑"是测不出来的，必须拿"直接上传"当基准对拍。
set -euo pipefail

cd "$(dirname "$0")/.."
export CGO_ENABLED=0

PA="${PORT_A:-}"   # 基准：直接上传 pcap
PB="${PORT_B:-}"   # 待测：探针上报
pick_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
[ -n "$PA" ] || PA="$(pick_port)"
[ -n "$PB" ] || PB="$(pick_port)"
BASE_A="http://127.0.0.1:${PA}"
BASE_B="http://127.0.0.1:${PB}"
TMP="$(mktemp -d)"
PCAPS="normal_office frp_tunnel clash_proxy reverse_proxy multi_net"

cleanup() {
  for p in A B; do
    eval "pid=\${PID_$p:-}"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

start_server() { # $1=port $2=tag
  local port="$1" tag="$2"
  cat > "$TMP/cfg_$tag.yaml" <<EOF
listen_addr: "127.0.0.1:${port}"
db_path: '$TMP/db_$tag.db'
probe_enabled: false
capture_enabled: false
EOF
  "$TMP/starmap" -config "$TMP/cfg_$tag.yaml" >"$TMP/server_$tag.log" 2>&1 &
  eval "PID_$tag=$!"
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$port/api/health" >/dev/null && return 0
    sleep 0.2
  done
  echo "服务 $tag 未就绪"; cat "$TMP/server_$tag.log"; exit 1
}

echo "[1/5] 构建"
go build -o "$TMP/starmap" ./cmd/starmap
go build -o "$TMP/starmap-probe" ./cmd/starmap-probe

echo "[2/5] 启动两个干净实例 A=$PA（基准） B=$PB（探针）"
start_server "$PA" A
start_server "$PB" B

echo "[3/5] A：直接上传 pcap"
for f in $PCAPS; do
  printf '  %-16s %s\n' "$f" "$(curl -sf -F "file=@testdata/out/$f.pcap" "$BASE_A/api/ingest/pcap")"
done

echo "[4/5] B：探针逐份回放上报"
for f in $PCAPS; do
  printf '  %-16s ' "$f"
  "$TMP/starmap-probe" \
    -source "file:testdata/out/$f.pcap" -once \
    -server "$BASE_B" -probe-id e2e-probe -name "E2E 探针" \
    -location "E2E 镜像口" 2>"$TMP/probe_$f.log" | tail -0 || true
  grep -o 'msg=回放结束.*' "$TMP/probe_$f.log" || { echo "探针失败"; cat "$TMP/probe_$f.log"; exit 1; }
done

echo "[5/5] 对拍"
python3 - "$BASE_A" "$BASE_B" <<'PYEOF'
import json, sys, urllib.request
a, b = sys.argv[1], sys.argv[2]

def get(base, p):
    with urllib.request.urlopen(base + p) as r:
        return json.load(r)

def ev_types(base):
    d = {}
    for e in get(base, "/api/events"):
        d[e["Type"]] = d.get(e["Type"], 0) + 1
    return d

ta, tb = ev_types(a), ev_types(b)
ok = True
print(f"  基准事件: {dict(sorted(ta.items()))}")
print(f"  探针事件: {dict(sorted(tb.items()))}")
for t in sorted(set(ta) | set(tb)):
    na, nb = ta.get(t, 0), tb.get(t, 0)
    good = na == nb
    ok &= good
    print(f"    {t:<14} 基准 {na} 探针 {nb} " + ("OK" if good else "FAIL"))
if not ta:
    print("  基准没有任何事件，测试无意义"); ok = False

# 拓扑：探针会自动注册自身节点，所以节点数允许探针侧多，不允许少。
sa = get(a, "/api/topology")["Stats"]
sb = get(b, "/api/topology")["Stats"]
print(f"  拓扑基准: nodes={sa['NodeCount']} edges={sa['EdgeCount']}")
print(f"  拓扑探针: nodes={sb['NodeCount']} edges={sb['EdgeCount']}")
ok &= sb["NodeCount"] >= sa["NodeCount"] and sb["EdgeCount"] >= sa["EdgeCount"]

if not ok:
    print("探针对拍失败"); sys.exit(1)
print("  探针与直接上传结果一致 ✅")
PYEOF

echo "端到端通过 ✅"
