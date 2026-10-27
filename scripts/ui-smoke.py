"""StarMap 前端交互冒烟（真浏览器）。

这是 1.1.0 唯一没进 CI 的测试层：Web 包里的 `pages_test.go` 只能证明"页面骨架和令牌没漂移"，
证明不了"点下去会怎样"。本脚本补的是后者——真开一个 Chromium，跑导航、下钻、登录、角色门禁、
1.2 的深度发现弹窗，以及 1.3.1 的**列表真·服务端分页与搜索**。

不进 CI 的原因：需要下载浏览器（内网/CI 都可能拉不动），且慢。定位为**发布前手动闸门**：
    make ui                               # 用默认实例 127.0.0.1:18097
    make ui BASE=http://127.0.0.1:18080   # 或指定实例
    AUTH_BASE=http://127.0.0.1:18096 ...  # 额外测登录与角色门禁
    AUTH_BASE=                            # 或置空，跳过认证部分

要求后端已灌数据（PCAP + simprobe），否则拓扑为空会跳过下钻用例而不是失败。
分页用例同理：事件不足一页时跳过翻页断言，但**搜索、通配符转义、limit 夹取**这三项
与数据量无关，空库也会验——它们正是"看着正常但结论是错的"那类问题的高发区。

深度发现只测"弹窗能开、档位计划对得上、空/非法目标拦得住"，**不真扫**：
真扫会打内网，且要 discover_enabled，跨环境不可控；扫描的端到端在
internal/api/discover_test.go 里用 httptest 覆盖。

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
    """拓扑：画布渲染 + 网段下钻 + 返回。

    聚合网段看的是 /api/subnets 的 aggregated 标记，不是 /api/topology 的节点 ID：
    /api/topology 出的是引擎原始节点（IP/MAC 维度），`subnet:` 前缀要等聚合后才有，
    早先版本在 /api/topology 里找 `subnet:` 前缀，永远找不到，这段用例一直在空转。
    """
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)

    cidrs = [s["cidr"] for s in pg.request.get(f"{BASE}/api/subnets").json()
             if s.get("aggregated")]
    if not cidrs:
        # 合成 PCAP 每个 /24 只有两三台，够不到默认聚合阈值（20）。
        # 阈值本来就是运行时参数，临时降到 1 让聚合发生，比跳过用例更有价值。
        pg.request.put(f"{BASE}/api/config", data={"aggregate_threshold": 1})
        pg.wait_for_timeout(3500)  # 引擎每 2s 重算一次
        cidrs = [s["cidr"] for s in pg.request.get(f"{BASE}/api/subnets").json()
                 if s.get("aggregated")]
    if not cidrs:
        skipped.append("[拓扑] 没有 /24 聚合网段（数据太少且阈值降不下来），跳下钻用例")
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


def smoke_discover(br):
    """深度发现（1.2）：三档端口计划、弹窗结构、空/非法目标拦得住。"""
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)

    counts = {}
    for k in ("quick", "standard", "full"):
        r = pg.request.get(f"{BASE}/api/discover/plan?profile={k}")
        if r.status != 200:
            skipped.append(f"[发现] /api/discover/plan?profile={k} 返回 {r.status}（后端可能未升到 1.2）")
            ctx.close()
            return
        counts[k] = r.json()["port_count"]
    check(counts["quick"] < counts["standard"] < counts["full"],
          f"[发现] 三档端口数未递增: {counts}")
    check(counts["quick"] >= 50, f"[发现] quick 档端口过少: {counts['quick']}")
    check(counts["full"] == 65535, f"[发现] full 档应覆盖 1-65535，实际 {counts['full']}")
    check(pg.request.get(f"{BASE}/api/discover/plan?profile=nope").status == 400,
          "[发现] 非法档位应 400")

    pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
    # 「深度发现」挂在「端口记录」这个 tab 里，不是首屏
    pg.click('.sm-tab[data-tab="ports"]')
    pg.wait_for_timeout(400)
    entry = pg.locator('[data-act="discover"]')
    if entry.count() == 0:
        skipped.append("[发现] 当前身份看不到「深度发现」入口（viewer 门禁或旧版页面）")
        ctx.close()
        return
    entry.click()
    pg.wait_for_selector(".sm-modal", timeout=4000)
    check("深度发现" in pg.inner_text(".sm-modal-title"), "[发现] 弹窗标题不符")
    check(pg.locator("#dProfile option").count() == 3, "[发现] 档位下拉不是 3 项")
    check(pg.locator("#dFingerprint").is_checked(), "[发现] 指纹勾选默认未开")

    sent = []
    pg.on("request", lambda r: sent.append(r.url) if "/api/discover/run" in r.url else None)

    # 空目标：前端拦，请求根本不该发出去
    pg.click('[data-act="sm-modal-ok"]')
    pg.wait_for_timeout(700)
    check(not sent, f"[发现] 空目标仍发出了 {len(sent)} 个 /api/discover/run 请求")
    check("请填写扫描目标" in pg.inner_text("body"), "[发现] 空目标没有提示")
    check(pg.locator(".sm-modal").count() == 1, "[发现] 空目标后弹窗被关掉了（应留着让人填）")
    check(not errors, f"[发现] 控制台错误: {errors}")

    # 非法目标：后端 4xx/503，前端要如实报错并保留弹窗，不能假装成功。
    # 这一步会故意打出 4xx，浏览器必然记一条 "Failed to load resource"，
    # 所以只断言没有 JS 异常，不再拿 console 日志当缺陷。
    pg.fill("#dTarget", "这不是地址")
    pg.click('[data-act="sm-modal-ok"]')
    pg.wait_for_timeout(1500)
    check(pg.locator(".sm-toast.is-err").count() >= 1, "[发现] 非法目标没有错误提示")
    check(pg.locator(".sm-modal").count() == 1, "[发现] 非法目标后弹窗被关掉了")
    check("关闭" not in pg.inner_text('[data-act="sm-modal-ok"]'),
          "[发现] 失败时按钮不该变成「关闭」")

    pg.click('[data-act="sm-modal-close"]')
    pg.wait_for_timeout(300)
    check(pg.locator(".sm-modal").count() == 0, "[发现] 关闭按钮没关掉弹窗")
    js_errors = [e for e in errors if e.startswith("pageerror")]
    check(not js_errors, f"[发现] JS 异常: {js_errors}")
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


def api_json(pg, path):
    """用浏览器上下文请求接口，返回 (json, headers)。"""
    r = pg.request.get(BASE + path)
    if not r.ok:
        return None, {}
    try:
        return r.json(), r.headers
    except Exception:
        return None, {}


def poll(pg, fn, timeout=8.0, interval=0.2):
    """轮询直到 fn() 为真。比 wait_for_function 稳：不依赖页面里注入的 JS 表达式。"""
    import time
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def smoke_paging(br):
    """列表的真·服务端分页与搜索（1.3.1）。

    分页最容易出的错不是"翻不动"，而是这两类**静默错误**：
      1. 翻过去了，但拿到的还是同一批数据（页码变了内容没变）；
      2. 筛选只在当前页生效——用户搜不到上限之外的数据，却得到"没有匹配"的答案，
         于是确信那台机器不存在。第 2 类比第 1 类危险得多，所以重点验它。

    不假设数据量：空库/小库自动跳过需要多页的断言，只验"分页参数确实生效"。
    """
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    errors = []
    pg = new_page(ctx, errors)
    pg.goto(f"{BASE}/events.html", wait_until="networkidle")

    # ---- 分页契约（API 层） ----
    _, h1 = api_json(pg, "/api/events?limit=5&offset=0")
    n_total = int(h1.get("x-total-count") or 0)
    check(int(h1.get("x-result-limit") or 0) == 5,
          f"[分页] limit=5 未回显 X-Result-Limit（实际 {h1.get('x-result-limit')}）")

    page1, _ = api_json(pg, "/api/events?limit=5&offset=0")
    page2, _ = api_json(pg, "/api/events?limit=5&offset=5")
    if n_total > 5 and page1 and page2:
        ids1 = {e.get("ID") for e in page1}
        ids2 = {e.get("ID") for e in page2}
        check(ids1.isdisjoint(ids2), "[分页] 第 1/2 页返回了重复事件（排序键不稳定）")
    else:
        skipped.append("[分页] 事件不足 6 条，跳过翻页断言")

    # limit 必须被夹取，否则 ?limit=1e9 等于要求把整表读进内存
    _, h2 = api_json(pg, "/api/events?limit=999999&offset=0")
    check(int(h2.get("x-result-limit") or 0) == 5000, "[分页] limit 未被夹取到 5000")

    # ---- 搜索在服务端生效 ----
    kw = "frp"
    found, fh = api_json(pg, f"/api/events?q={kw}&limit=50&offset=0")
    if found:
        bad = [e.get("ID") for e in found
               if kw not in ((e.get("Title") or "") + (e.get("Detail") or "")).lower()]
        check(not bad, f"[搜索] 服务端返回了不含关键字的条目（说明筛选没下沉到 SQL）: {bad[:5]}")
    n_found = int(fh.get("x-total-count") or 0)
    check(n_found <= n_total, f"[搜索] 过滤后总数 {n_found} 大于全量 {n_total}")

    # ---- LIKE 通配符必须转义 ----
    # 不转义时搜 "%" 会命中全部记录，用户会以为"搜索坏了"
    pct, ph = api_json(pg, "/api/events?q=%25&limit=50&offset=0")
    if pct:
        bad = [e.get("ID") for e in pct
               if "%" not in ((e.get("Title") or "") + (e.get("Detail") or ""))]
        check(not bad, f"[搜索] 搜字面量 % 却命中了不含 % 的记录（通配符未转义）: {bad[:5]}")
    check(int(ph.get("x-total-count") or 0) < n_total or n_total == 0,
          "[搜索] 搜 % 命中了全部记录，LIKE 通配符未转义")

    # ---- UI：翻页必须换数据 ----
    if n_total > 20:
        pg.goto(f"{BASE}/events.html", wait_until="networkidle")
        pg.select_option("#fStatus", "")          # 页面默认只看「待处置」，先放开
        got_rows = poll(pg, lambda: pg.locator("#list table tbody tr").count() == 20)
        if got_rows:
            sel = "#list table tbody tr button[data-act=open]"
            before = set(pg.eval_on_selector_all(sel, "els => els.map(e => e.dataset.id)"))
            pg.locator("#pager button[data-page='2']").first.click()
            changed = poll(pg, lambda: not (set(pg.eval_on_selector_all(
                sel, "els => els.map(e => e.dataset.id)")) & before))
            check(changed, "[分页] 点第 2 页后表格内容没变（服务端分页未生效）")
        else:
            skipped.append("[分页] 事件列表未渲染满 20 行，跳过 UI 翻页断言")
    else:
        skipped.append("[分页] 事件不足 21 条，跳过 UI 翻页断言")

    # ---- UI：资产页搜索走后端 ----
    pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
    if poll(pg, lambda: pg.locator("#assetTable tbody tr").count() > 0):
        n_asset = int((api_json(pg, "/api/assets?limit=1&offset=0")[1]).get("x-total-count") or 0)
        before = pg.inner_text("#cntBadge").strip()
        pg.fill("#fKw", "zzz-不存在的关键字-zzz")
        # 关键：不能只等"徽标变成 0 台"——徽标初值就是 0 台，会立刻"满足"。
        # 必须等它发生变化后再判断，否则断言在页面还没更新时就跑完了。
        narrowed = poll(pg, lambda: (lambda t: t != before and "0 台" in t)(pg.inner_text("#cntBadge").strip()))
        if narrowed:
            check(True, "[搜索] 资产页无匹配时徽标归零（总数与列表同源）")
            check("没有符合条件" in pg.inner_text("#assetTable"),
                  "[搜索] 无匹配时未显示筛选态空态文案")
            # 清空关键字必须恢复全量（不能把本地 filter 的残留带回去）
            pg.fill("#fKw", "")
            check(poll(pg, lambda: pg.inner_text("#cntBadge").strip() == f"{n_asset} 台"),
                  f"[搜索] 清空关键字后未恢复全量 {n_asset} 台（实际 {pg.inner_text('#cntBadge')!r}）")
        else:
            skipped.append("[搜索] 资产页搜索未生效，跳过（可能资产为空）")
    else:
        skipped.append("[搜索] 资产表为空，跳过资产搜索断言")

    check(not errors, f"[分页] 页面控制台错误: {errors}")
    ctx.close()


def main() -> int:
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        smoke_pages(br)
        smoke_topology(br)
        smoke_discover(br)
        smoke_paging(br)
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
