"""StarMap 前端交互冒烟（真浏览器）。

这是 1.1.0 唯一没进 CI 的测试层：Web 包里的 `pages_test.go` 只能证明"页面骨架和令牌没漂移"，
证明不了"点下去会怎样"。本脚本补的是后者——真开一个 Chromium，跑导航、下钻、登录、角色门禁。

不进 CI 的原因：需要下载浏览器（内网/CI 都可能拉不动），且慢。定位为**发布前手动闸门**：
    python scripts/ui-smoke.py            # 只测无认证实例（默认 127.0.0.1:18097）
    AUTH_BASE=http://127.0.0.1:18096 ...  # 额外测登录与角色门禁

要求后端已灌数据（PCAP + simprobe），否则拓扑为空会跳过下钻用例而不是失败。

用法：
  /c/Users/41935/.workbuddy/binaries/python/envs/deploy/Scripts/python.exe scripts/ui-smoke.py
退出码：0 全通过；1 有断言失败（打印明细）。
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "http://127.0.0.1:18097")
AUTH_BASE = os.environ.get("AUTH_BASE", "http://127.0.0.1:18096")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
VIEWER_USER = os.environ.get("VIEWER_USER", "auditor")
PASSWORD = os.environ.get("PASSWORD", "StarMap@2026")

PAGES = ["index.html", "assets.html", "events.html", "whitelist.html",
         "domains.html", "ingest.html", "settings.html", "logs.html", "about.html"]

fails = []
skipped = []


def check(cond, msg):
    if not cond:
        fails.append(msg)
    return cond


def any_marked(page, timeout=6000):
    """等待任一 [data-role] 元素出现；空库/按需渲染的页面返回 False 而不是抛异常。"""
    try:
        page.wait_for_selector('[data-role="operator"], [data-role="admin"]',
                               state="attached", timeout=timeout)
        return True
    except Exception:
        return False


def visible_count(page, selector):
    return page.evaluate(
        """(sel) => Array.prototype.filter.call(
              document.querySelectorAll(sel),
              el => el.offsetParent !== null && getComputedStyle(el).visibility !== 'hidden'
           ).length""",
        selector,
    )


def new_page(ctx, errors):
    pg = ctx.new_page()
    pg.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    return pg


def smoke_pages(br):
    """9 个页面：骨架渲染、导航项、页脚版本号与后端一致、无控制台错误。"""
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)

    health = pg.request.get(f"{BASE}/api/health").json()
    version = health.get("version", "")

    for path in PAGES:
        errors.clear()
        pg.goto(f"{BASE}/{path}", wait_until="networkidle")
        tag = f"[页面] {path}"

        check("StarMap" in pg.title(), f"{tag} 标题缺少产品名: {pg.title()!r}")
        check(pg.inner_text(".sm-topbar .sm-brand-name").strip() == "星图", f"{tag} 顶栏品牌未渲染")
        check(pg.locator("#smSider .sm-navitem").count() >= 9, f"{tag} 侧栏导航项不足 9 个")
        check(pg.locator(".sm-footer").count() == 1, f"{tag} 页脚缺失")
        footer = pg.inner_text("#smFooterVer")
        check(version and version in footer, f"{tag} 页脚版本 {footer!r} 与 /api/health {version!r} 不一致")
        check(not errors, f"{tag} 控制台错误: {errors}")

    # 页头结构：pill 分组标签 + 大标题
    pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
    check(pg.locator(".sm-pagehd .sm-pill").count() == 1, "[页头] 缺少分组 pill")
    check(pg.inner_text(".sm-pagehd .sm-h1").strip() == "主机资产", "[页头] 大标题不符")

    # 侧栏导航真的能跳，并同步高亮
    pg.goto(f"{BASE}/index.html", wait_until="networkidle")
    pg.click("#smSider .sm-navitem:has-text('主机资产')")
    pg.wait_for_load_state("networkidle")
    check(pg.url.endswith("assets.html"), f"[导航] 未跳到资产页，实际 {pg.url}")
    check("is-active" in pg.get_attribute("#smSider .sm-navitem:has-text('主机资产')", "class"),
          "[导航] 当前项未高亮")

    ctx.close()


def smoke_topology(br):
    """拓扑：下钻与返回。数据为空时跳过（不算失败）。"""
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)

    topo = pg.request.get(f"{BASE}/api/topology").json()
    cidrs = [n["ID"][len("subnet:"):] for n in topo.get("Nodes", [])
             if str(n.get("ID", "")).startswith("subnet:")]
    if not cidrs:
        skipped.append("[拓扑] 当前数据没有 /24 聚合节点，跳下钻用例")
        ctx.close()
        return

    pg.goto(f"{BASE}/index.html", wait_until="networkidle")
    pg.wait_for_timeout(2500)
    check(pg.locator(".sm-topo-node").count() > 0, "[拓扑] 画布上没有节点")

    cidr = cidrs[0]
    pg.evaluate("(c) => drilldown(c)", cidr)
    pg.wait_for_timeout(2000)
    check(pg.locator("#btnBack").is_visible(), f"[拓扑] 下钻 {cidr} 后未出现「返回上级」")
    check(pg.locator(".sm-topo-node").count() > 0, "[拓扑] 下钻后画布为空")

    pg.click("#btnBack")
    pg.wait_for_timeout(1500)
    check(not pg.locator("#btnBack").is_visible(), "[拓扑] 返回后按钮未被隐藏")
    check(not errors, f"[拓扑] 控制台错误: {errors}")
    ctx.close()


def login(pg, user):
    pg.goto(f"{AUTH_BASE}/login", wait_until="networkidle")
    pg.fill("#username", user)
    pg.fill("#password", PASSWORD)
    pg.click("#submit")
    pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(800)


def smoke_auth(br):
    """登录流程 + 角色门禁真的收敛到 DOM 上。"""
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)

    # --- admin：能看到写操作入口 ---
    login(pg, ADMIN_USER)
    check("/login" not in pg.url, f"[登录] {ADMIN_USER} 登录后仍停在登录页")
    chip = pg.locator(".sm-userchip")
    check(chip.count() == 1, "[登录] 顶栏身份胶囊缺失")
    me = pg.request.get(f"{AUTH_BASE}/api/auth/me", headers={}).json()
    # 胶囊显示的是 display_name（系统管理员），不是账号名——两者都算通过
    shown = pg.inner_text(".sm-userchip")
    check(me.get("subject") in shown or me.get("display_name", "\x00") in shown,
          f"[登录] 身份胶囊与 /api/auth/me 不一致: 胶囊={shown!r} me={me}")

    # 用「系统配置」页做正向断言：保存按钮是静态渲染的，
    # 不像资产表那样依赖"库里有数据"，否则空库环境会把测试环境问题当成 UI 缺陷。
    pg.goto(f"{AUTH_BASE}/settings.html", wait_until="networkidle")
    pg.wait_for_timeout(600)
    admin_ops = visible_count(pg, '[data-role="operator"], [data-role="admin"]')
    check(admin_ops > 0, "[角色] admin 看不到任何写操作入口（门禁可能把该显示的也藏了）")
    check(all(not e for e in errors), f"[admin] 控制台错误: {errors}")
    ctx.close()

    # --- viewer：写操作入口必须消失 ---
    ctx2 = br.new_context(viewport={"width": 1440, "height": 900})
    errs2 = []
    pg2 = new_page(ctx2, errs2)
    login(pg2, VIEWER_USER)
    check("/login" not in pg2.url, f"[登录] {VIEWER_USER} 登录失败")
    role = pg2.evaluate("() => document.documentElement.getAttribute('data-sm-role')")
    check(role == "viewer", f"[角色] <html data-sm-role> 应为 viewer，实际 {role!r}")

    # 只在"必然有写操作入口"的页面断言必须存在；其余页面（事件抽屉、空表）按钮是
    # 按需渲染到 DOM 的，存在时才要求全部隐藏。
    always = [("assets.html", "资产删除/扫描"), ("settings.html", "保存配置"), ("ingest.html", "抓包/探测")]
    maybe = [("events.html", "复核"), ("whitelist.html", "删除"), ("domains.html", "删除")]
    for path, label in always:
        pg2.goto(f"{AUTH_BASE}/{path}", wait_until="networkidle")
        if not any_marked(pg2):
            skipped.append(f"[角色] {path} 当前没有 {label} 入口（空库环境），跳过")
            continue
        shown = visible_count(pg2, '[data-role="operator"], [data-role="admin"]')
        check(shown == 0, f"[角色] {path} 上 viewer 仍看得到 {shown} 个写操作入口（{label}）")
    for path, label in maybe:
        pg2.goto(f"{AUTH_BASE}/{path}", wait_until="networkidle")
        pg2.wait_for_timeout(600)
        shown = visible_count(pg2, '[data-role="operator"], [data-role="admin"]')
        check(shown == 0, f"[角色] {path} 上 viewer 仍看得到 {shown} 个写操作入口（{label}）")

    # 后端才是唯一判定点：直接发请求照样 403
    status = pg2.request.put(f"{AUTH_BASE}/api/config", data={"aggregate_threshold": 30}).status
    check(status == 403, f"[角色] viewer 直连 PUT /api/config 应 403，实际 {status}")
    ctx2.close()


def main() -> int:
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        smoke_pages(br)
        smoke_topology(br)
        if AUTH_BASE:
            smoke_auth(br)
        br.close()

    for s in skipped:
        print(f"SKIP {s}")
    if fails:
        print(f"\n失败 {len(fails)} 项：")
        for f in fails:
            print(" -", f)
        return 1
    print("\n前端交互冒烟通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
