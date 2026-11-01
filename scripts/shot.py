"""StarMap 星图运行截图（1.1.0 起为刻本口径 UI）。

前置：起一个灌好数据的服务（见 docs/screenshots/README.md 的复现步骤），
再指定 STARBASE 运行。登录页需要 auth.mode=local 的实例（STARLOGIN 指向它）。

深度发现那张要真扫一轮，所以默认不拍：设 STARDISCOVER 为目标才会执行，
且该实例需 discover_enabled: true。

只更新部分截图用 SHOTONLY（逗号分隔的输出文件名），避免拿数据较少的实例
把整批截图覆盖成更差的版本：
  SHOTONLY=settings.png,discover.png

用法（deploy venv + msedge，免下载浏览器）：
  STARBASE=http://127.0.0.1:18097 \
  STARLOGIN=http://127.0.0.1:18096 \
  /c/Users/41935/.workbuddy/binaries/python/envs/deploy/Scripts/python.exe scripts/shot.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("STARBASE", "http://127.0.0.1:18097")
LOGIN_BASE = os.environ.get("STARLOGIN") or BASE
DISCOVER_TARGET = os.environ.get("STARDISCOVER", "")
ONLY = {s.strip() for s in os.environ.get("SHOTONLY", "").split(",") if s.strip()}
OUT = (os.environ.get("SHOTOUT") or
       os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "screenshots")))
os.makedirs(OUT, exist_ok=True)

VIEWPORT = {"width": 1440, "height": 900}


def want(name):
    """SHOTONLY 为空时全拍；否则只拍点名的。"""
    return not ONLY or name in ONLY

# (页面, 输出文件名, 额外等待秒数)
PAGES = [
    ("index.html", "topology.png", 5.0),
    ("assets.html", "assets.png", 1.6),
    ("sites.html", "sites.png", 2.4),
    ("changes.html", "changes.png", 2.6),
    ("tasks.html", "tasks.png", 1.8),
    ("domains.html", "domains.png", 1.4),
    ("whitelist.html", "whitelist.png", 1.4),
    ("ingest.html", "ingest.png", 1.4),
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
            if not want(name):
                continue
            pg.goto(f"{BASE}/{path}", wait_until="networkidle")
            shoot(pg, name, wait)

        # 风险事件：列表默认只筛"待处置"，那正是给处置用的默认值。
        # 但截图要证明"复核能让状态变化"，所以切到「全部状态」再拍——
        # 否则图里永远是清一色"待处置"，看不出处置这条链路走过没有。
        if want("events.png"):
            pg.goto(f"{BASE}/events.html", wait_until="networkidle")
            pg.wait_for_timeout(900)
            pg.select_option("#fStatus", "")
            shoot(pg, "events.png", 1.8)

        # 站点详情：1.7 的一级资产视图，抽屉里是证书情报 + 人工标注表单。
        # 光拍列表证明不了抽屉能用——标注表单是这一页唯一的写入口。
        if want("site-detail.png"):
            pg.goto(f"{BASE}/sites.html", wait_until="networkidle")
            pg.wait_for_timeout(1500)
            pg.click('button[data-act="open"]')
            pg.wait_for_selector("#drawer.is-open", timeout=4000)
            pg.wait_for_timeout(600)
            # 抽屉正文可滚动，默认停在顶部时标注表单会被页脚切掉半行（标签框只露一条边）。
            # 滚到标签输入框：既保住上面的证书情报，又能把"标签 + 备注 + 保存标注"整块拍全。
            pg.evaluate("""() => {
                var n = document.getElementById('mTags');
                if (n) { n.scrollIntoView({block: 'center'}); }
            }""")
            shoot(pg, "site-detail.png", 1.2)

        # 任务详情：1.6 的任务账，抽屉里给的是"每台主机扫出哪些端口"
        if want("task-detail.png"):
            pg.goto(f"{BASE}/tasks.html", wait_until="networkidle")
            pg.wait_for_timeout(1200)
            if pg.locator('button[data-act="open"]').count() > 0:
                pg.click('button[data-act="open"]')
                pg.wait_for_selector("#drawer.is-open", timeout=4000)
                shoot(pg, "task-detail.png", 1.4)

        # 报表：/api/report 是一份自包含的 HTML，浏览器直接打开就该能看能打印
        if want("report.png"):
            pg.goto(f"{BASE}/api/report", wait_until="networkidle")
            shoot(pg, "report.png", 1.2)

        # 设置页：1.2 新增的「资产与扫描」在首屏之下，滚过去拍才看得到
        if want("settings.png"):
            pg.goto(f"{BASE}/settings.html", wait_until="networkidle")
            pg.wait_for_timeout(800)
            pg.evaluate("""() => {
                var h = Array.prototype.filter.call(
                    document.querySelectorAll('.sm-card-hd h2'),
                    function (x) { return x.textContent.trim() === '资产与扫描'; })[0];
                if (h) { h.scrollIntoView({block: 'start'}); window.scrollBy(0, -72); }
            }""")
            shoot(pg, "settings.png", 0.8)

        # 台账对照：资产页的第三个标签。
        # 默认停在「全部」时，表格按 账外→在册→IP不符→僵尸 排，首屏全是"台账外"，
        # 看起来像"网里全是影子设备"；而这些行的归属/位置必然为空（台账里没有），
        # 恰恰拍不出"导入台账后把归属单位、负责人、物理位置补上了"这件事。
        # 所以切到「在册在网」再拍：四类计数仍在上面的卡片与筛选标签里。
        if want("ledger.png"):
            pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
            pg.click('button[data-tab="ledger"]')
            pg.wait_for_timeout(800)
            pg.click('#ledgerFilters .sm-tab:has-text("在册在网")')
            shoot(pg, "ledger.png", 2.0)

        # 端口记录：1.2 起有「指纹」列（产品 / 版本 / 证书 / favicon）
        if want("ports.png"):
            pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
            pg.click('button[data-tab="ports"]')
            shoot(pg, "ports.png", 1.6)

        # 深度发现：真扫一轮再看结果（需 discover_enabled: true）
        if want("discover.png") and DISCOVER_TARGET:
            pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
            pg.click('button[data-tab="ports"]')
            pg.wait_for_timeout(400)
            pg.click('[data-act="discover"]')
            pg.wait_for_selector(".sm-modal", timeout=4000)
            pg.fill("#dTarget", DISCOVER_TARGET)
            pg.click('[data-act="sm-modal-ok"]')
            pg.wait_for_selector('#dStatus .sm-alert.is-ok', timeout=180000)
            shoot(pg, "discover.png", 0.8)
            pg.click('[data-act="sm-modal-close"]')
            pg.wait_for_timeout(300)

        # 下钻：进入被聚合的网段（与 topology.png 里的聚合节点一致）
        if want("topology-drill.png"):
            pg.goto(f"{BASE}/index.html", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.evaluate("drilldown('10.10.1.0/24')")
            shoot(pg, "topology-drill.png", 4.5)  # 等 toast 淡出，截图里不留浮层

        # XFF：点开反代节点，右侧详情列出被还原的客户端。
        # 这张要用更高的视口，否则「通信对端」列表被裁在折线以下。
        if want("topology-xff.png"):
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
        if LOGIN_BASE != BASE and want("login.png"):
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
