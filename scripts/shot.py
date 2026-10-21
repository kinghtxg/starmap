"""StarMap 星图运行截图（1.1.0 起为刻本口径 UI）。

前置：起一个灌好数据的服务（见 docs/screenshots/README.md 的复现步骤），
再指定 STARBASE 运行。登录页需要 auth.mode=local 的实例（STARLOGIN 指向它）。

用法（deploy venv + msedge，免下载浏览器）：
  STARBASE=http://127.0.0.1:18097 \
  STARLOGIN=http://127.0.0.1:18096 \
  /c/Users/41935/.workbuddy/binaries/python/envs/deploy/Scripts/python.exe scripts/shot.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("STARBASE", "http://127.0.0.1:18097")
LOGIN_BASE = os.environ.get("STARLOGIN", BASE)
OUT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "screenshots"))
os.makedirs(OUT, exist_ok=True)

VIEWPORT = {"width": 1440, "height": 900}

# (页面, 输出文件名, 额外等待秒数)
PAGES = [
    ("index.html", "topology.png", 5.0),
    ("assets.html", "assets.png", 1.6),
    ("events.html", "events.png", 1.8),
    ("domains.html", "domains.png", 1.4),
    ("whitelist.html", "whitelist.png", 1.4),
    ("ingest.html", "ingest.png", 1.4),
    ("settings.html", "settings.png", 1.4),
    ("logs.html", "logs.png", 1.4),
]


def shoot(page, name, wait=1.2):
    page.wait_for_timeout(int(wait * 1000))
    fp = os.path.join(OUT, name)
    page.screenshot(path=fp)
    print(f"OK  {name:<20} {os.path.getsize(fp) / 1024:>6.0f} KB")


def main() -> int:
    errors = []
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        ctx = br.new_context(viewport=VIEWPORT, device_scale_factor=2)
        pg = ctx.new_page()
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: errors.append(str(e)))

        for path, name, wait in PAGES:
            pg.goto(f"{BASE}/{path}", wait_until="networkidle")
            shoot(pg, name, wait)

        # 台账对照：资产页的第三个标签
        pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
        pg.click('button[data-tab="ledger"]')
        shoot(pg, "ledger.png", 2.0)

        # 下钻：进入被聚合的网段（与 topology.png 里的聚合节点一致）
        pg.goto(f"{BASE}/index.html", wait_until="networkidle")
        pg.wait_for_timeout(2500)
        pg.evaluate("drilldown('10.10.1.0/24')")
        shoot(pg, "topology-drill.png", 4.5)  # 等 toast 淡出，截图里不留浮层

        # XFF：点开反代节点，右侧详情列出被还原的客户端。
        # 这张要用更高的视口，否则「通信对端」列表被裁在折线以下。
        pg.set_viewport_size({"width": 1440, "height": 1180})
        pg.goto(f"{BASE}/index.html", wait_until="networkidle")
        pg.wait_for_timeout(2500)
        pg.evaluate("""() => {
            var list = (window.snapshot && snapshot.Nodes) || [];
            var n = list.filter(function (x) {
                return (x.Labels || []).indexOf('xff-proxy') >= 0;
            })[0];
            if (n) showDetail(n.ID);
        }""")
        shoot(pg, "topology-xff.png", 3.0)
        pg.set_viewport_size(VIEWPORT)

        # 登录页（auth.mode=local 的实例）
        if LOGIN_BASE != BASE:
            pg.goto(f"{LOGIN_BASE}/login", wait_until="networkidle")
            shoot(pg, "login.png", 1.2)

        ctx.close()
        br.close()

    if errors:
        print("\n浏览器控制台错误（应为空）：")
        for e in errors:
            print(" -", e)
        return 1
    print("\nOUT:", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
