#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""StarMap 全功能 API 冒烟测试"""
import json, sys, urllib.request, urllib.error

BASE = "http://127.0.0.1:18080"
PASS = 0
FAIL = 0

def req(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            txt = resp.read().decode()
            return resp.status, (json.loads(txt) if txt else None)
    except urllib.error.HTTPError as e:
        txt = e.read().decode()
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, txt
    except Exception as e:
        return -1, str(e)

def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")

print("========== 基础 ==========")
s, d = req("GET", "/api/health")
check("health", s == 200 and d.get("status") == "ok", str(d))

print("========== 拓扑 ==========")
s, d = req("GET", "/api/topology")
check("topology 快照", s == 200 and "Nodes" in d and "Edges" in d, str(s))

print("========== 探测 ==========")
# 探测目标：示例网段（请按实际环境修改，或用 127.0.0.1 本机测试）
PROBE_IP = "192.168.1.1"
PROBE_CIDR = "192.168.1.0/24"
s, d = req("POST", "/api/probe/trigger", {"type": "icmp", "target": PROBE_IP})
check("ICMP 单 IP", s == 200 and len(d.get("Hosts", [])) >= 1, f"hosts={d.get('Hosts') if isinstance(d,dict) else d}")

s, d = req("POST", "/api/probe/trigger", {"type": "icmp", "target": PROBE_CIDR})
check("ICMP /24 网段（曾报无法解析）", s == 200, f"code={s} resp={str(d)[:120]}")

s, d = req("POST", "/api/probe/trigger", {"type": "arp", "target": PROBE_CIDR})
check("ARP /24 网段", s == 200, f"code={s}")

s, d = req("POST", "/api/probe/trigger", {"type": "traceroute", "target": PROBE_IP})
check("traceroute", s == 200, f"code={s}")

print("========== 资产库 ==========")
s, d = req("GET", "/api/assets/stats")
check("资产统计", s == 200 and "total" in d, str(d))
s, d = req("GET", "/api/assets")
check("资产列表", s == 200 and isinstance(d, list), str(s))
if isinstance(d, list) and d:
    unarch = [a for a in d if a.get("status") == "unarchived"]
    if unarch:
        key = unarch[0]["node_key"]
        s, d2 = req("POST", "/api/assets/archive", {"node_key": key, "owner": "测试", "department": "测试部", "os": "TestOS"})
        check("资产归档", s == 200 and d2.get("ok") == True, str(d2))
        s, d2 = req("PUT", f"/api/assets/{key}", {"owner": "测试2"})
        check("资产维护", s == 200, str(d2))
        # 不删最后一个资产，避免影响演示；仅验证接口存在
        s, d2 = req("DELETE", f"/api/assets/{key}")
        check("资产删除", s == 200, str(d2))

print("========== 端口记录 ==========")
s, d = req("GET", "/api/ports")
check("端口列表", s == 200 and isinstance(d, list), str(s))
print(f"      当前端口记录 {len(d) if isinstance(d,list) else 0} 条")

print("========== 数据接入 ==========")
import urllib.parse, pathlib
def upload(name):
    path = f"testdata/out/{name}"
    if not pathlib.Path(path).exists():
        return -1, "文件不存在"
    boundary = "----testboundary"
    with open(path, "rb") as f:
        content = f.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    r = urllib.request.Request(BASE + "/api/ingest/pcap", data=body, method="POST")
    r.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]

for name in ["frp_tunnel.pcap", "clash_proxy.pcap", "reverse_proxy.pcap", "multi_net.pcap", "normal_office.pcap"]:
    s, d = upload(name)
    check(f"导入 {name}", s == 200, f"code={s} {d}")

print("========== 事件 ==========")
s, d = req("GET", "/api/events")
check("事件列表", s == 200, str(s))
evs = d if isinstance(d, list) else (d.get("Events", []) if isinstance(d, dict) else [])
types = set()
for e in evs:
    types.add(e.get("Type"))
print(f"      事件 {len(evs)} 条，类型: {sorted(types)}")
check("检测出隧道/融合事件", bool(types & {"frp", "clash", "multi_net", "reverse_proxy", "unknown_egress"}), str(types))

print("========== 配置 ==========")
s, d = req("GET", "/api/config")
check("配置读取", s == 200 and "scan_ports" in d, str(s))
check("全端口扫描默认值", d.get("scan_ports") == "1-65535", str(d.get("scan_ports")))

print("========== 审计日志 ==========")
s, d = req("GET", "/api/audit")
check("审计日志", s == 200 and isinstance(d, list), str(s))
if isinstance(d, list):
    actions = set(x.get("Action") for x in d)
    check("日志记录归档/扫描操作", bool(actions & {"asset_archive", "asset_delete", "probe_trigger"}), str(actions))

print("========== 未注册 API（应为 JSON 404 而非 HTML） ==========")
s, d = req("GET", "/api/foobar")
check("未注册 API 返回 JSON 404", s == 404 and isinstance(d, dict) and "error" in d, f"code={s} resp={str(d)[:80]}")

print()
print(f"========== 结果: {PASS} 通过 / {FAIL} 失败 ==========")
sys.exit(1 if FAIL else 0)
