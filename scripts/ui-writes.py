"""写入口回归：把界面上的每个写操作真点一遍，并用服务端回读验收。

为什么单开一个脚本：`ui-smoke.py` 管的是"点下去会怎样"（导航、分页、搜索、角色门禁），
`visual-audit.py` 管的是"排版对不对"。**没有一层在验"写进去的东西真的落库了"**——
而"toast 提示成功、接口 200、数据没落库"恰恰是最难发现的一类失败。

每个用例都自己清理自己造的数据（创建即删除、改完再还原），跑完实例回到原样。
数据量不足时**跳过而不是失败**：这一层验的是写路径，不是"这台机器有没有数据"。

用法：
  BASE=http://127.0.0.1:18097 python3 scripts/ui-writes.py
  BASE=... python3 scripts/ui-writes.py --keep    # 保留造的数据，便于人工看界面
退出码：0 全通过；1 有断言失败（打印明细）。
"""
import json
import os
import sys
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE") or "http://127.0.0.1:18097"
KEEP = "--keep" in sys.argv

fails = []
skipped = []


def check(cond, msg, extra=""):
    print(("  OK  " if cond else "  FAIL") + f"  {msg}" + (f"   {extra}" if extra else ""))
    if not cond:
        fails.append(msg)
    return cond


def skip(msg):
    print(f"  SKIP  {msg}")
    skipped.append(msg)


def api(path, data=None, method=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method)
    with urllib.request.urlopen(req) as r:
        body = r.read().decode()
    return json.loads(body) if body.strip() else None


def toast(pg, expect="", timeout=8000):
    """等一条「含 expect 文案的 toast」出现，再取最后一条。

    同屏可能还挂着上一条（3s 才淡出），取第一条会读到旧文案，
    于是把"其实成功了"判成失败。断言必须等目标文案，不能等"任意 toast"。
    """
    pg.wait_for_function(
        """(exp) => Array.from(document.querySelectorAll('.sm-toast'))
                     .some(n => n.textContent.indexOf(exp) >= 0)""",
        arg=expect, timeout=timeout)
    return pg.locator(".sm-toast").last.inner_text()


def modal_ok(pg):
    pg.click('[data-act="sm-modal-ok"]')


def new_page(ctx):
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    return pg, errors


# ---------------------------------------------------------------- 用例

def case_domain(pg):
    """网络域：新建 → 改名 → 删除，全部服务端回读。"""
    print("[网络域] 新建 → 编辑 → 删除")
    pg.goto(f"{BASE}/domains.html", wait_until="networkidle")
    pg.wait_for_timeout(800)
    n0 = pg.locator(".sm-card").count()

    pg.click('.sm-pagehd [data-act="create"]')
    pg.wait_for_selector("#dName", timeout=5000)
    pg.fill("#dName", "回归测试域")
    pg.fill("#dCIDRs", "203.0.113.0/24\n198.51.100.0/24")
    pg.fill("#dColorVal", "#7b61ff")
    modal_ok(pg)
    check("已保存" in toast(pg, "已保存"), "新建返回成功")
    pg.wait_for_timeout(900)
    check(pg.locator(".sm-card").count() == n0 + 1, "列表卡片数 +1", f"{n0} → {n0 + 1}")

    card = pg.locator('.sm-card:has-text("回归测试域")')
    card.locator('[data-act="edit"]').click()
    pg.wait_for_selector("#dName", timeout=5000)
    check(pg.input_value("#dName") == "回归测试域", "编辑弹窗回填原值")
    pg.fill("#dName", "回归测试域-改")
    modal_ok(pg)
    check("已保存" in toast(pg, "已保存"), "编辑返回成功")
    pg.wait_for_timeout(900)
    check(pg.locator('.sm-card:has-text("回归测试域-改")').count() == 1, "改名已生效")

    if not KEEP:
        pg.locator('.sm-card:has-text("回归测试域-改")').locator('[data-act="del"]').click()
        pg.wait_for_selector(".sm-mask", timeout=5000)
        modal_ok(pg)
        check("已删除" in toast(pg, "已删除"), "删除返回成功")
        pg.wait_for_timeout(900)
        check(pg.locator(".sm-card").count() == n0, "卡片数回到初始值")
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(600)
        check(pg.locator('.sm-card:has-text("回归测试域")').count() == 0, "刷新后确认未落库")


def case_whitelist(pg):
    """白名单：新建 → 改备注 → 删除。"""
    print("[白名单] 新建 → 编辑 → 删除")
    pg.goto(f"{BASE}/whitelist.html", wait_until="networkidle")
    pg.wait_for_timeout(800)
    value = "203.0.113.88"

    pg.click('.sm-pagehd [data-act="create"]')
    pg.wait_for_selector("#wValue", timeout=5000)
    pg.select_option("#wKind", "ip")
    pg.fill("#wValue", value)
    pg.fill("#wNote", "回归测试")
    modal_ok(pg)
    check("已保存" in toast(pg, "已保存"), "新建返回成功")
    pg.wait_for_timeout(900)
    row = pg.locator(f'tr:has-text("{value}")')
    check(row.count() == 1, "新条目出现在表格")
    check("回归测试" in row.inner_text(), "备注已落库")

    row.locator('[data-act="edit"]').click()
    pg.wait_for_selector("#wNote", timeout=5000)
    pg.fill("#wNote", "回归测试-已编辑")
    modal_ok(pg)
    check("已保存" in toast(pg, "已保存"), "编辑返回成功")
    pg.wait_for_timeout(900)
    check("已编辑" in pg.locator(f'tr:has-text("{value}")').inner_text(), "备注已更新")

    if not KEEP:
        pg.locator(f'tr:has-text("{value}")').locator('[data-act="del"]').click()
        pg.wait_for_selector(".sm-mask", timeout=5000)
        modal_ok(pg)
        check("已删除" in toast(pg, "已删除"), "删除返回成功")
        pg.wait_for_timeout(900)
        check(pg.locator(f'tr:has-text("{value}")').count() == 0, "删除后表格里没有它")


def case_event(pg):
    """事件处置：备注必填要拦得住，填完后状态与计数都要变。"""
    print("[风险事件] 处置（含必填校验）")
    pg.goto(f"{BASE}/events.html", wait_until="networkidle")
    pg.wait_for_timeout(1200)
    if pg.locator('[data-act="open"]').count() == 0:
        skip("没有待处置事件，跳过事件处置")
        return
    before = pg.inner_text("#sumLine")

    pg.locator('[data-act="open"]').first.click()
    pg.wait_for_selector("#drawer.is-open", timeout=5000)
    # 备注为空时点处置：必须被拦住，而不是"静默成功"
    pg.click('[data-act="review"][data-v="defer"]')
    t = toast(pg, "请填写处置备注")
    check("请填写处置备注" in t, "空备注被拦下（不是默默成功）", t)
    check(pg.locator("#drawer.is-open").count() == 1, "被拦下时抽屉仍开着")

    pg.fill("#rvReviewer", "qa")
    pg.fill("#rvNote", "回归测试：确认已知风险")
    pg.click('[data-act="review"][data-v="confirm"]')
    t = toast(pg, "已确认")
    check("已确认" in t, "处置返回成功", t)
    pg.wait_for_timeout(1200)
    check(pg.locator("#drawer.is-open").count() == 0, "处置后抽屉自动关闭")
    after = pg.inner_text("#sumLine")
    check(after != before, "汇总行发生变化（待处置数下降）", f"{before} → {after}")


def case_asset(pg):
    """资产：归档登记 → 编辑 → 删除，每次都回读服务端。"""
    print("[主机资产] 归档 → 编辑 → 删除")
    pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
    pg.wait_for_timeout(1200)
    btn = pg.locator('[data-act="archive"]')
    if btn.count() == 0:
        skip("没有未归档主机，跳过归档用例")
        return
    row = pg.locator("tr").filter(has=pg.locator('[data-act="archive"]')).first
    ip = row.locator("td").first.inner_text().strip().split("\n")[0]
    row.locator('[data-act="archive"]').click()
    pg.wait_for_selector("#fDept", timeout=5000)
    pg.fill("#fDept", "信息中心")
    pg.fill("#fOwner", "qa")
    pg.fill("#fHost", "regress-host")
    modal_ok(pg)
    check("已归档登记" in toast(pg, "已归档登记"), "归档返回成功")
    pg.wait_for_timeout(1000)

    def asset_of(ip_):
        for a in api(f"/api/assets?kw={ip_}&limit=50"):
            if ip_ in (a.get("ips") or []):
                return a
        return None

    a = asset_of(ip)
    check(a and a["status"] == "archived", "服务端回读 status=archived", a and a["status"])
    check(a and a["department"] == "信息中心", "归属单位已落库", a and a["department"])

    pg.fill("#fKw", ip)
    pg.wait_for_timeout(1200)
    row = pg.locator(f'tr:has-text("{ip}")').first
    row.locator('[data-act="edit"]').click()
    pg.wait_for_selector("#fDept", timeout=5000)
    check(pg.input_value("#fDept") == "信息中心", "编辑弹窗回填归属单位")
    pg.fill("#fDesc", "回归测试")
    modal_ok(pg)
    check("已保存" in toast(pg, "已保存"), "编辑返回成功")
    pg.wait_for_timeout(900)
    a = asset_of(ip)
    check(a and a["description"] == "回归测试", "备注已更新", a and a["description"])

    if not KEEP:
        row.locator('[data-act="del"]').click()
        pg.wait_for_selector(".sm-mask", timeout=5000)
        modal_ok(pg)
        check("已删除" in toast(pg, "已删除"), "删除返回成功")
        pg.wait_for_timeout(1000)
        check(asset_of(ip) is None, "服务端回读已不存在")


def case_ledger(pg):
    """台账对照：导入 → 四类计数 → 模板下载 → 清空。

    台账必须能同时讲清四类差异，否则这一页"账实对照"的结论是没有说服力的：
      在册在网（IP+MAC 都对） / 台账僵尸（台账有网内无） /
      IP 不符（MAC 命中但 IP 变了） / 台账外（网内其余主机）。
    """
    print("[台账对照] 导入 → 分类计数 → 模板 → 清空")
    hosts = [h for h in api("/api/assets?limit=200") if h.get("mac") and h.get("ips")]
    if len(hosts) < 2:
        skip("带 MAC 的主机不足 2 台，跳过台账用例")
        return
    a, b = hosts[0], hosts[1]
    csv = ("IP地址,MAC地址,主机名,归属单位\n"
           f"{a['ips'][0]},{a['mac']},regress-a,信息中心\n"          # 在册在网
           f"10.99.99.99,02:00:00:00:00:99,gone-pc,档案室\n"          # 台账僵尸
           # MAC 在网内 b 上、但写的 IP 是另一个 → IP 不符
           f"10.88.88.88,{b['mac']},moved-pc,外联部\n")

    pg.goto(f"{BASE}/assets.html", wait_until="networkidle")
    pg.wait_for_timeout(1000)
    pg.click('[data-tab="ledger"]')
    pg.wait_for_timeout(700)

    def led_total():
        return pg.evaluate("""() => {
            const n = document.querySelector('#ledgerSummary .sm-stat-val[data-v]');
            return n ? Number(n.getAttribute('data-v')) : 0;
        }""")

    # 这一例要验的是「空态 → 导入 → 四类计数 → 清空」，前提是台账为空。
    # 库里可能留着上一次跑剩下的台账（清空失败或带 --keep 跑过），不清就会把
    # "上一轮的遗留"读成"空态文案没出现"——那是前置条件没摆好，不是产品缺陷。
    if led_total():
        pg.click('[data-act="ledger-clear"]')
        pg.wait_for_selector(".sm-mask", timeout=5000)
        modal_ok(pg)
        pg.wait_for_timeout(1200)
    check("尚未导入" in pg.inner_text("#ledgerSummary"), "未导入时是空态文案")

    pg.click('[data-act="ledger-import"]')
    pg.wait_for_selector("#lText", timeout=5000)
    pg.fill("#lText", csv)
    with pg.expect_download(timeout=15000) as d:
        pg.click('[data-act="ledger-template"]')
    dl = d.value
    size = os.path.getsize(dl.path()) if dl.path() else 0
    check(size > 0 and dl.suggested_filename.endswith(".csv"), "模板导出为真实文件",
          f"{dl.suggested_filename} {size}B")

    pg.click('[data-act="sm-modal-ok"]')
    check("导入" in toast(pg, "导入"), "导入返回成功")
    pg.wait_for_timeout(1600)

    cards = pg.evaluate("""() => {
        const o = {};
        document.querySelectorAll('#ledgerSummary .sm-stat').forEach(c => {
            o[c.querySelector('.sm-stat-key').textContent.trim()] =
              Number(c.querySelector('.sm-stat-val').getAttribute('data-v'));
        });
        return o;
    }""")
    check(cards.get("台账条目") == 3, "台账条目 = 3", str(cards))
    check(cards.get("在册在网", 0) >= 1, "在册在网 ≥ 1", str(cards))
    check(cards.get("台账僵尸") == 1, "台账僵尸 = 1（10.99.99.99 网内无）", str(cards))
    # 「IP 不符」不在顶部四张卡里，它在筛选标签上带数字——按卡片取会恒得 0 而误判成缺陷
    kinds = pg.evaluate("""() => {
        const o = {};
        document.querySelectorAll('#ledgerFilters .sm-tab').forEach(b => {
            const t = b.textContent.trim().split(/\\s+/);
            o[t[0]] = Number(t[t.length - 1]);
        });
        return o;
    }""")
    check(kinds.get("IP") == 1, "IP 不符 = 1（MAC 命中但 IP 变了）", str(kinds))

    if not KEEP:
        pg.click('[data-act="ledger-clear"]')
        pg.wait_for_selector(".sm-mask", timeout=5000)
        modal_ok(pg)
        check("已清空" in toast(pg, "已清空"), "清空返回成功")
        pg.wait_for_timeout(1200)
        check("尚未导入" in pg.inner_text("#ledgerSummary"), "清空后回到未导入空态")


def case_settings(pg):
    """配置保存：改值 → 保存 → 回读 → 还原；同时守「保存按钮随时可达」。"""
    print("[系统配置] 保存 + 吸底可达性")
    key = "#cfg_aging_seconds"

    def btn(sel):
        return pg.evaluate("""(sel) => {
            const b = document.querySelector(sel);
            if (!b) return null;
            const r = b.getBoundingClientRect();
            return {top: Math.round(r.top), inView: r.top >= 0 && r.bottom <= innerHeight + 1};
        }""", sel)

    pg.goto(f"{BASE}/settings.html", wait_until="networkidle")
    pg.wait_for_selector(key, timeout=8000)
    hd = btn('.sm-pagehd [data-act="save"]')
    check(hd and hd["inView"], "顶部：页头保存按钮在视口内", str(hd))
    op = pg.evaluate("() => getComputedStyle(document.getElementById('actionbar')).opacity")
    check(float(op) < 0.05, "顶部：吸底条隐藏（不出现两套保存按钮）", f"opacity={op}")

    pg.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
    pg.wait_for_timeout(500)
    hd = btn('.sm-pagehd [data-act="save"]')
    bar = btn('#actionbar [data-act="save"]')
    check(hd and not hd["inView"], "滚到底部：页头按钮已离开视口", str(hd))
    check(bar and bar["inView"], "滚到底部：吸底条按钮在视口内", str(bar))

    old = pg.input_value(key)
    new = "43200" if old != "43200" else "86400"
    pg.fill(key, new)
    pg.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
    pg.wait_for_timeout(300)
    pg.click('#actionbar [data-act="save"]')
    check("已保存" in toast(pg, "已保存"), "吸底条保存返回成功")

    pg.wait_for_timeout(800)
    pg.goto(f"{BASE}/settings.html", wait_until="networkidle")
    pg.wait_for_selector(key, timeout=8000)
    check(pg.input_value(key) == new, "reload 后回读一致（真的落库）", f"{new} == {pg.input_value(key)}")

    pg.fill(key, old)
    pg.click('.sm-pagehd [data-act="save"]')
    check("已保存" in toast(pg, "已保存"), "还原保存成功")
    pg.wait_for_timeout(800)
    pg.goto(f"{BASE}/settings.html", wait_until="networkidle")
    pg.wait_for_selector(key, timeout=8000)
    check(pg.input_value(key) == old, "已还原", f"{old} == {pg.input_value(key)}")


def case_task_stop(pg):
    """停止运行中的扫描：status 要变 cancelled，且进度必须真的冻结。"""
    print("[发现任务] 启动 → 停止")
    start = api("/api/discover/run", {"targets": ["10.0.0.0/24"], "profile": "quick"})
    tid = start.get("task_id")
    if not tid:
        check(False, "启动扫描失败，无法验证停止", str(start))
        return

    pg.goto(f"{BASE}/tasks.html", wait_until="networkidle")
    pg.wait_for_timeout(1500)
    row = pg.locator(f'tr:has-text("{tid}")').first
    check(row.count() == 1, "列表里能看到刚起的任务")
    row.locator('[data-act="open"]').click()
    pg.wait_for_selector("#drawer.is-open", timeout=5000)
    pg.wait_for_timeout(600)

    stop = pg.locator('#drawerFt [data-act="stop"]')  # 表格行里也有一个「停止」，这里要点抽屉那个
    check(stop.count() == 1, "运行中的任务详情里有「停止任务」")
    stop.click()
    pg.wait_for_selector(".sm-mask", timeout=5000)
    modal_ok(pg)
    pg.wait_for_timeout(2500)

    st = api(f"/api/tasks/{tid}")
    check(st["status"] == "cancelled", "服务端 status=cancelled", st["status"])
    done1 = st["done"]
    pg.wait_for_timeout(3000)
    st2 = api(f"/api/tasks/{tid}")
    check(st2["done"] == done1, "停止后进度不再增长（扫描真的停了）", f"{done1} → {st2['done']}")


def case_exports(pg):
    """四处导出：任务账 / 站点 / 端口记录 / 拓扑图。

    导出必须等 download 事件并核对文件名与字节数——只断言"toast 出现了"等于没测。
    """
    print("[导出] 任务账 / 站点 / 端口 / 拓扑图")
    for path, sel, label, ext in [
        ("tasks.html", '.sm-pagehd [data-act="export"]', "任务账", ".csv"),
        ("sites.html", '.sm-pagehd [data-act="export"]', "站点", ".csv"),
        ("changes.html", '[data-act="export-ports"]', "端口记录", ".csv"),
        ("index.html", '[data-act="png"]', "拓扑图", ".png"),
        ("index.html", '[data-act="svg"]', "拓扑图", ".svg"),
    ]:
        pg.goto(f"{BASE}/{path}", wait_until="networkidle")
        pg.wait_for_timeout(2500 if path == "index.html" else 1500)
        trigger = pg.locator(sel)
        if trigger.count() == 0:
            skip(f"{label}页面没有导出入口 {sel}")
            continue
        with pg.expect_download(timeout=20000) as d:
            trigger.first.click()
        dl = d.value
        size = os.path.getsize(dl.path()) if dl.path() else 0
        check(size > 0 and dl.suggested_filename.endswith(ext),
              f"{label}导出为真实文件", f"{dl.suggested_filename} {size}B")


def case_capture_disabled(pg):
    """抓包不可用时：按钮禁用 + 页面写明原因，而不是点了才报错。"""
    print("[数据接入] 抓包不可用的表达")
    pg.goto(f"{BASE}/ingest.html", wait_until="networkidle")
    pg.wait_for_timeout(1200)
    btn = pg.locator('[data-act="cap-start"]')
    if btn.count() == 0:
        skip("数据接入页没有抓包入口")
        return
    cls = btn.get_attribute("class") or ""
    if "is-disabled" in cls:
        body = pg.inner_text(".sm-content")
        check("未编译" in body or "不可用" in body, "抓包不可用时页面写明原因")
        check(True, "抓包按钮处于禁用态（点不动而不是点了才报错）")
    else:
        pg.click('[data-act="cap-start"]')
        check(bool(toast(pg, timeout=15000)), "抓包启动给出明确回执")


def main() -> int:
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        ctx = br.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
        pg, errors = new_page(ctx)

        for fn in (case_domain, case_whitelist, case_event, case_asset, case_ledger,
                   case_settings, case_task_stop, case_exports, case_capture_disabled):
            try:
                fn(pg)
            except Exception as e:  # 单个用例崩掉不该让后面的全不跑
                check(False, f"{fn.__name__} 抛异常", str(e)[:160])
        check(not errors, "全程无 pageerror", str(errors[:3]))
        ctx.close()
        br.close()

    for s in skipped:
        print(f"SKIP {s}")
    if fails:
        print(f"\n失败 {len(fails)} 项：")
        for f in fails:
            print(" -", f)
        return 1
    print("\n写入口回归通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
