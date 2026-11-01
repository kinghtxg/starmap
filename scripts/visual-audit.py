"""逐页视觉回归：横向溢出、文字被裁、元素出界、控件过小、控制台报错。

为什么要有这个脚本：用肉眼看截图判断布局是不可靠的——缩放会把"正常"看成
"被裁"，也会把"被裁"看成"正常"。这里全部用 scrollWidth/clientWidth 与
getBoundingClientRect 实测，给出发版前可复现的闸门。

用法（需要先在 STARBASE 上起一个灌过数据的实例）：
  STARBASE=http://127.0.0.1:18097 \
  /c/Users/41935/.workbuddy/binaries/python/envs/deploy/Scripts/python.exe scripts/visual-audit.py
  STARBASE=... python scripts/visual-audit.py --wide   # 另跑一遍 2560 宽，看宽屏拉伸

退出码非 0 表示有页面不达标，可直接进 CI 或作为发版前的最后一步。
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("STARBASE") or "http://127.0.0.1:18097"
WIDE = "--wide" in sys.argv

PAGES = [
    ("index.html", "拓扑总览"),
    ("assets.html", "主机资产"),
    ("events.html", "风险事件"),
    ("sites.html", "站点资产"),
    ("changes.html", "变更"),
    ("tasks.html", "发现任务"),
    ("domains.html", "网络域"),
    ("whitelist.html", "白名单"),
    ("ingest.html", "数据接入"),
    ("logs.html", "审计日志"),
    ("settings.html", "系统配置"),
    ("about.html", "关于"),
    # 报表是一份自包含 HTML，会被单独存下来发出去，排版问题在别人那儿才暴露，
    # 所以它也要过同一套闸门（1.7.1 那条 /favicon.ico 404 就是在这里抓出来的）。
    ("api/report", "资产测绘报告"),
]

# 低于这个高度的可点击控件算"手不好点"（桌面端 24px，触屏建议 32px）
MIN_TAP = 24

PROBE = r"""
(minTap) => {
  const out = {docOverflow: document.documentElement.scrollWidth - window.innerWidth,
               clipped: [], outOfView: [], tiny: []};
  const seen = new Set();
  const HTML = 'http://www.w3.org/1999/xhtml';
  document.querySelectorAll('body *').forEach(el => {
    // SVG 里的 <text> 没有 clientWidth（恒为 0），按 HTML 的裁切判据会整片假阳性；
    // 拓扑图上的标签是被画布裁剪的，不是 CSS 裁切。
    if (el.namespaceURI !== HTML) return;
    // 固定定位层里的一切（抽屉/遮罩/浮层）都不参与：抽屉常驻 DOM 停在
    // right:1920，只排除它自己不够，子元素照样报"出界"。
    if (el.closest('.sm-drawer, .sm-mask, .sm-toasts')) return;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' ||
        cs.opacity === '0' || cs.position === 'fixed') return;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;

    if (el.children.length === 0 && el.scrollWidth > el.clientWidth + 2 &&
        (cs.whiteSpace === 'nowrap' || cs.overflow !== 'visible') &&
        cs.textOverflow !== 'ellipsis') {
      const key = el.tagName + '|' + (el.className || '') + '|' + el.textContent.slice(0, 18);
      if (!seen.has(key)) { seen.add(key);
        out.clipped.push({sel: key, sw: el.scrollWidth, cw: el.clientWidth,
                          text: el.textContent.trim().slice(0, 28)}); }
    }
    if (r.right > window.innerWidth + 1 || r.left < -1) {
      out.outOfView.push({tag: el.tagName, cls: (el.className || '').toString().slice(0, 40),
                          left: Math.round(r.left), right: Math.round(r.right),
                          text: el.textContent.trim().slice(0, 24)});
    }
    // 只量真正的控件：页脚那种行内文字链接（关于/隐私/审计）17px 高是排版不是缺陷，
    // 把它们算进"手不好点"只会让人习惯性忽略这条告警。
    const isBtn = /^(BUTTON|SELECT|INPUT|TEXTAREA)$/.test(el.tagName) ||
                  (el.tagName === 'A' && /(^|\s)(sm-btn|sm-iconbtn)(\s|$)/.test(el.className || ''));
    if (isBtn && r.height < minTap) {
      out.tiny.push({tag: el.tagName, h: Math.round(r.height),
                     text: (el.textContent || el.placeholder ||
                            el.getAttribute('aria-label') || '').trim().slice(0, 20)});
    }
  });
  out.outOfView = out.outOfView.slice(0, 8);
  out.tiny = out.tiny.slice(0, 8);
  return out;
}
"""

# 配置页专项：长表单滚到底部时，唯一的保存入口必须在视口内。
# 这条曾经真的坏过——页头不吸顶，滚到底部时按钮在 4400px 之外。
SETTINGS_BOTTOM = r"""
() => {
  const bar = document.querySelector('#actionbar [data-act="save"]');
  const hd = document.querySelector('.sm-pagehd [data-act="save"]');
  if (!bar || !hd) return {miss: true};
  window.scrollTo(0, document.documentElement.scrollHeight);
  return new Promise(res => setTimeout(() => {
    const r = bar.getBoundingClientRect();
    res({inView: r.top >= 0 && r.bottom <= innerHeight + 1 && r.height > 0,
         top: Math.round(r.top), bottom: Math.round(r.bottom), vh: innerHeight});
  }, 400));
}
"""


def main() -> int:
    bad = []
    shots = {"width": 2560, "height": 1440} if WIDE else {"width": 1440, "height": 900}
    print(f"视口 {shots['width']}x{shots['height']}  ·  站点 {BASE}\n")
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge")
        ctx = br.new_context(viewport=shots)
        for path, label in PAGES:
            pg = ctx.new_page()
            errs, http = [], []
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.on("console", lambda m: errs.append("console:" + m.text) if m.type == "error" else None)
            pg.on("response", lambda r: http.append(f"{r.status} {r.url}") if r.status >= 400 else None)

            pg.goto(f"{BASE}/{path}", wait_until="networkidle")
            pg.wait_for_timeout(1800)
            r = pg.evaluate(PROBE, MIN_TAP)

            problems = []
            if r["docOverflow"] > 0:
                problems.append(f"横向溢出 {r['docOverflow']}px")
            for c in r["clipped"]:
                problems.append(f"文字被裁 {c['sw']}>{c['cw']} {c['text']!r}")
            for o in r["outOfView"]:
                problems.append(f"元素出界 left={o['left']} right={o['right']} {o['tag']} {o['text']!r}")
            for t in r["tiny"]:
                problems.append(f"控件过小 h={t['h']} {t['tag']} {t['text']!r}")
            for e in errs:
                problems.append(f"脚本异常 {e[:80]}")
            for h in http:
                problems.append(f"请求失败 {h[:100]}")

            if path == "settings.html":
                b = pg.evaluate(SETTINGS_BOTTOM)
                if b.get("miss"):
                    problems.append("配置页找不到吸底保存条")
                elif not b["inView"]:
                    problems.append(f"滚到底部时保存按钮不在视口内 top={b['top']}")

            tag = "PASS" if not problems else "FAIL"
            print(f"[{tag}] {label:<8} {path}")
            for x in problems:
                print("       -", x)
                bad.append(f"{path}: {x}")
            pg.close()
        ctx.close()
        br.close()

    print()
    if bad:
        print(f"共 {len(bad)} 项不达标")
        return 1
    print("全部页面通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
