package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// 前端契约测试（无浏览器依赖）。
//
// 为什么用这种形式而不是等 Playwright：
// 本项目最容易被改坏的不是交互逻辑，而是**页面骨架与设计令牌的一致性**——
// 新增一个页面忘了套 sm-topbar / sm-sider，或者某处又写回旧版深色，
// 编译、Go 单测、接口 e2e 全都发现不了，只有人肉点开页面才看得见。
// 这里把「页面必须长什么样」固化成断言，CI 里秒级就能拦住这类漂移。
//
// 真正的浏览器交互（拓扑点击下钻、抽屉、角色门禁的实际显示）仍是待补项，
// 见 docs/RELEASE-1.0.md「已知短板」。

func readWeb(t *testing.T, name string) string {
	t.Helper()
	b, err := FS.ReadFile(name)
	if err != nil {
		t.Fatalf("读取内嵌资源 %s 失败: %v", name, err)
	}
	return string(b)
}

// 所有业务页面共享的骨架与资源引用。
func TestPagesShareSkeleton(t *testing.T) {
	pages := []string{
		"index.html", "assets.html", "events.html", "whitelist.html",
		"domains.html", "ingest.html", "settings.html", "logs.html", "about.html",
		// V1.6 新增：变更视图与主动发现任务账
		"changes.html", "tasks.html",
	}
	required := []struct {
		frag string
		why  string
	}{
		{`class="sm-app"`, "缺少应用容器（布局的定位根）"},
		{`class="sm-topbar" id="smTopbar"`, "缺少全局顶栏挂载点（品牌 + 搜索 + 身份胶囊）"},
		{`id="smSider"`, "缺少侧栏挂载点"},
		{`class="sm-main"`, "缺少内容区容器"},
		{`class="sm-pagehd"`, "缺少页头（pill 标签 + 大标题 + 操作区）"},
		{`class="sm-pill"`, "页头缺少分组 pill 标签"},
		{`href="assets/theme.css"`, "未引用设计系统样式"},
		{`src="assets/app.js"`, "未引用布局脚本（顶栏/侧栏/页脚靠它渲染）"},
		{`lang="zh-CN"`, "缺少语言声明"},
	}
	for _, p := range pages {
		src := readWeb(t, p)
		if !strings.Contains(src, "<!DOCTYPE html>") && !strings.Contains(src, "<!doctype html>") {
			t.Errorf("%s: 缺少 DOCTYPE", p)
		}
		if !strings.Contains(src, "</html>") {
			t.Errorf("%s: 文档未闭合", p)
		}
		if !strings.Contains(src, "StarMap") {
			t.Errorf("%s: 标题/文案里没有产品名", p)
		}
		for _, r := range required {
			if !strings.Contains(src, r.frag) {
				t.Errorf("%s: %s —— 期望包含 %q", p, r.why, r.frag)
			}
		}
		// 页面级样式只允许走 theme.css：内联 <style> 一多，设计令牌就会各自漂移
		if strings.Contains(src, "<style") {
			t.Errorf("%s: 不允许内联 <style>，样式请加到 assets/theme.css", p)
		}
	}
}

// 旧版深色视觉不得回流。
func TestNoLegacyDarkTheme(t *testing.T) {
	legacy := []string{"#0F172A", "#0f172a", "#1E293B", "#1e293b", "#38BDF8", "#38bdf8"}
	entries := []string{"login.html", "assets/theme.css", "assets/app.js"}
	for _, p := range entries {
		src := readWeb(t, p)
		for _, c := range legacy {
			if strings.Contains(src, c) {
				t.Errorf("%s: 出现旧版深色 %s，刻本口径应为浅色画布", p, c)
			}
		}
	}
}

// 设计令牌必须是刻本口径，否则"全面模仿刻本"就名存实亡。
func TestThemeTokensMatchKeben(t *testing.T) {
	css := readWeb(t, "assets/theme.css")
	must := map[string]string{
		"主色":  "#3370ff",
		"画布":  "#f6f7fa",
		"侧栏":  "#f9fafb",
		"主文本": "#1f2329",
		"次文本": "#646a73",
		"描边":  "#e5e6e8",
		"语义红": "#e64545",
		"语义绿": "#1aa179",
	}
	for name, val := range must {
		if !strings.Contains(strings.ToLower(css), strings.ToLower(val)) {
			t.Errorf("theme.css 缺少刻本%s令牌 %s", name, val)
		}
	}
	// 顶栏 56px、侧栏 260px、圆角 6（控件）/10（容器）是刻本的布局口径
	for _, frag := range []string{"56px", "260px", "--sm-r-sm: 6px", "--sm-r-md: 10px"} {
		if !strings.Contains(css, frag) {
			t.Errorf("theme.css 缺少布局口径 %q", frag)
		}
	}
}

// 角色门禁必须走 CSS 属性选择器：动态插入的行/菜单也要自动收敛。
func TestRoleGateCoversDynamicNodes(t *testing.T) {
	css := readWeb(t, "assets/theme.css")
	for _, sel := range []string{
		`html[data-sm-role="viewer"]`,
		`html[data-sm-role="operator"]`,
		`[data-role="admin"]`,
		`[data-role="operator"]`,
	} {
		if !strings.Contains(css, sel) {
			t.Errorf("theme.css 缺少角色门禁选择器 %q", sel)
		}
	}
	app := readWeb(t, "assets/app.js")
	for _, fn := range []string{"applyRoleGate", "renderTopbar", "renderFooter", "loadMe"} {
		if !strings.Contains(app, "function "+fn) {
			t.Errorf("app.js 缺少 %s()", fn)
		}
	}
	if !strings.Contains(app, "data-sm-role") {
		t.Error("app.js 未把角色写到 <html data-sm-role>，CSS 门禁不会生效")
	}
}

// 侧栏导航的每个 href 都必须有对应页面，避免点进去 404。
func TestNavLinksResolve(t *testing.T) {
	app := readWeb(t, "assets/app.js")
	re := regexp.MustCompile(`\{ href: '([a-z]+\.html)'`)
	matches := re.FindAllStringSubmatch(app, -1)
	if len(matches) < 9 {
		t.Fatalf("导航项数量异常，只解析到 %d 个（应有 9 个）", len(matches))
	}
	for _, m := range matches {
		if _, err := fs.Stat(FS, m[1]); err != nil {
			t.Errorf("导航指向不存在的页面: %s", m[1])
		}
	}
	// 分组 pill 必须存在，且只允许「测绘 / 运维」两类
	for _, g := range []string{"group: '测绘'", "group: '运维'"} {
		if !strings.Contains(app, g) {
			t.Errorf("导航缺少分组 %s", g)
		}
	}
}

// 登录页是唯一允许内联样式的页面（认证前置，不能依赖可能被拦截的资源），
// 但它也必须与刻本同口径，且不引入任何外部依赖。
func TestLoginPageStandaloneAndLight(t *testing.T) {
	src := readWeb(t, "login.html")
	if !strings.Contains(src, "--brand:#3370ff") {
		t.Error("登录页主色不是刻本蓝 #3370ff")
	}
	if !strings.Contains(src, "#f6f7fa") {
		t.Error("登录页画布不是刻本 #f6f7fa")
	}
	if strings.Contains(src, "<canvas") {
		t.Error("登录页不应再有星空 canvas（旧版深色视觉）")
	}
	for _, bad := range []string{"http://", "https://"} {
		// 允许出现在注释里说明来源，但不允许出现在标签属性中
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, bad) {
				t.Errorf("登录页引用了外部资源（内网部署不允许）: %s", trimmed)
			}
		}
	}
	if !strings.Contains(src, "StarMap") {
		t.Error("登录页缺少产品名")
	}
}
