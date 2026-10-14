"""StarMap V1.0 运行截图：拓扑总览 / 事件工作台 / 数据接入 / 网络域 / 白名单 / 审计日志。
用法（deploy venv + msedge，免下载浏览器）：
  /c/Users/41935/.workbuddy/binaries/python/envs/deploy/Scripts/python.exe scripts/shot.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("STARBASE", "http://127.0.0.1:18080")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "screenshots")
OUT = os.path.abspath(OUT)
os.makedirs(OUT, exist_ok=True)

PAGES = [
    ("index.html", "topology.png", 3.5),
    ("events.html", "events.png", 2.0),
    ("ingest.html", "ingest.png", 1.5),
    ("domains.html", "domains.png", 1.5),
    ("whitelist.html", "whitelist.png", 1.5),
    ("logs.html", "logs.png", 1.5),
]


def main() -> int:
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        pg = br.new_page(viewport={"width": 1440, "height": 900})
        for path, name, wait in PAGES:
            pg.goto(f"{BASE}/{path}", wait_until="networkidle")
            pg.wait_for_timeout(int(wait * 1000))
            fp = os.path.join(OUT, name)
            pg.screenshot(path=fp)
            print(f"OK  {name:<16} {os.path.getsize(fp) / 1024:.0f} KB")
        br.close()
    print("OUT:", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
