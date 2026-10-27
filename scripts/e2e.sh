#!/usr/bin/env bash
# StarMap 星图 V1.0 二进制级端到端验收脚本（ACCEPTANCE 11.3 流程）。
# 构建二进制 → 临时 db + 端口启动 → 上传 testdata/out 的 5 个合成 PCAP →
# 断言 4 类事件 / 拓扑 / review 三操作审计留痕 / 误报自动加白 / 重复上传去重。
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/sdk/go/bin:/tmp/sdk/go/bin:$PATH"
export CGO_ENABLED=0

PORT="${E2E_PORT:-18099}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d)"
# Git Bash 下 mktemp -d 返回形如 C:\Users\x\AppData\Local\Temp/tmp.xxx（带反斜杠）。
# 把这种路径塞进 YAML 双引号串会被当成转义序列（\U \T …），解析直接失败；
# 下面的 db_path 因此改用单引号（YAML 单引号串不做转义）。
trap 'kill "$(cat "$TMP/pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$TMP" 2>/dev/null || true' EXIT

echo "[1/6] 构建二进制"
go build -o "$TMP/starmap" ./cmd/starmap

cat > "$TMP/config.yaml" <<EOF
listen_addr: "127.0.0.1:${PORT}"
db_path: '$TMP/starmap.db'
probe_enabled: false
capture_enabled: false
EOF

echo "[2/6] 启动服务 $BASE"
"$TMP/starmap" -config "$TMP/config.yaml" >"$TMP/server.log" 2>&1 &
echo $! > "$TMP/pid"
for i in $(seq 1 50); do
  curl -sf "$BASE/api/health" >/dev/null && break
  sleep 0.2
  [ "$i" = 50 ] && { echo "服务未就绪"; cat "$TMP/server.log"; exit 1; }
done

echo "[3/6] 上传 5 个合成 PCAP"
for f in normal_office frp_tunnel clash_proxy reverse_proxy multi_net; do
  echo "  - $f.pcap: $(curl -sf -F "file=@testdata/out/$f.pcap" "$BASE/api/ingest/pcap")"
done

echo "[4/6] 断言事件矩阵 / 拓扑 / 去重"
python3 - "$BASE" <<'PYEOF'
import json, sys, urllib.request
base = sys.argv[1]
def get(p):
    with urllib.request.urlopen(base + p) as r: return json.load(r)
def post(p, body):
    req = urllib.request.Request(base + p, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r: return json.load(r)

evs = get("/api/events")
types = {}
for e in evs: types.setdefault(e["Type"], []).append(e)
expect = {"frp": 1, "clash": 1, "reverse_proxy": 1, "multi_net": 1}
ok = True
for t, n in expect.items():
    got = len(types.get(t, []))
    print(f"  事件 {t}: 期望 {n} 实际 {got} " + ("OK" if got == n else "FAIL"))
    ok &= got == n
topo = get("/api/topology")
print(f"  拓扑: nodes={topo['Stats']['NodeCount']} edges={topo['Stats']['EdgeCount']}")
ok &= topo["Stats"]["NodeCount"] > 0 and topo["Stats"]["EdgeCount"] > 0

# 去重：全部 pending 状态下重复上传 frp/rp → 不新建（§10.5）
import subprocess
n0 = len(get("/api/events"))
for f in ("frp_tunnel", "reverse_proxy"):
    subprocess.run(["curl", "-sf", "-F", f"file=@testdata/out/{f}.pcap",
                    base + "/api/ingest/pcap"], check=True, capture_output=True)
n1 = len(get("/api/events"))
print(f"  重复上传去重: {n0} -> {n1}")
ok &= n0 == n1

# review 三操作
frp = types["frp"][0]; clash = types["clash"][0]; mn = types["multi_net"][0]
wl0 = len(get("/api/whitelist"))
r = post(f"/api/events/{frp['ID']}/review", {"action": "confirm", "note": "e2e", "reviewer": "tester"})
ok &= r["Status"] == "confirmed"
r = post(f"/api/events/{clash['ID']}/review", {"action": "false_positive", "note": "e2e", "reviewer": "tester"})
ok &= r["Status"] == "false_positive"
wl1 = len(get("/api/whitelist"))
ok &= wl1 > wl0
print(f"  误报自动加白: {wl0} -> {wl1}")
r = post(f"/api/events/{mn['ID']}/review", {"action": "defer", "note": "e2e", "reviewer": "tester"})
ok &= r["Status"] == "deferred"
aud = {a["Action"] for a in get("/api/audit")}
for want in ("event_confirm", "event_false_positive", "event_defer", "whitelist_create", "ingest_pcap"):
    ok &= want in aud
print(f"  审计动作覆盖: {sorted(aud)}")
if not ok:
    print("E2E 断言失败"); sys.exit(1)
print("  全部断言通过")
PYEOF

echo "[5/6] 二次去重断言（confirm/pending 事件在 24h 窗口内不重复建单）"
before=$(curl -sf "$BASE/api/events" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')
curl -sf -F "file=@testdata/out/frp_tunnel.pcap" "$BASE/api/ingest/pcap" >/dev/null
curl -sf -F "file=@testdata/out/reverse_proxy.pcap" "$BASE/api/ingest/pcap" >/dev/null
after=$(curl -sf "$BASE/api/events" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')
echo "  events: $before -> $after"
# multi_net 已 defer（按 §10.5 不在去重集合，重新评估会再出 1 个 pending，属预期）
[ "$after" -le "$((before + 1))" ] || { echo "去重失败"; exit 1; }

echo "[6/6] E2E 全部通过 ✅"
