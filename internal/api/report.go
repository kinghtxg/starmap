package api

// 单文件 HTML 报表（V1.7）。
//
// 灯塔那类产品的报表是"交出去"的产物：给等保整改、给资产对账、给领导看。
// CSV 解决的是"数据搬走"，报表解决的是"结论能直接读"——两者不是一回事。
//
// 三个约束决定了实现形态：
//  1. **单文件、零外链**。内网部署常常连不上外网，一份引用了 CDN 字体或
//     图表的报表拿出去就是白页。所以 CSS 内联、无脚本、无图片。
//  2. **可以直接 Ctrl+P 存 PDF**。加 @media print 规则，去掉圆角和阴影，
//     分页时表头重复。
//  3. **必须模板转义**。页面标题直接来自被扫描主机返回的 <title>，
//     是百分百的外部可控内容。用 text/template 拼字符串等于给自己开 XSS——
//     报表会被下载、转发、用浏览器打开，攻击面比后台页面更大。

import (
	"fmt"
	"html/template"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/model"
	"starmap/internal/store"
	"starmap/internal/version"
)

// reportData 渲染报表所需的数据（模板只认这个结构）。
type reportData struct {
	Version   string
	Generated time.Time
	Days      int
	Since     time.Time

	Nodes, Edges, Assets, Ports, Events, Pending int
	Sites                                        *model.SiteStats

	Expiring []model.Site
	Untagged []model.Site
	Added    []store.SiteChange
	Removed  []store.SiteChange
}

// reportHTML 报表模板。
//
// 用 html/template 而不是拼字符串：所有站点标题/证书 CN/备注都会自动转义。
const reportHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>StarMap 星图 · 资产测绘报告</title>
<!-- 图标内联成 data URI，保持"单文件可离线保存/发邮件"这条：换成 /assets/favicon.svg
     这类站内相对路径，一旦报表被单独存下来打开就成了死链。而完全不写这一行，
     浏览器会去请求 /favicon.ico，在没有该路由的实例上留一条 404 控制台报错。 -->
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%233370ff'/%3E%3Ccircle cx='16' cy='16' r='4.5' fill='%23fff'/%3E%3C/svg%3E">
<style>
  :root { --ink:#1f2329; --ink2:#4e5969; --ink3:#86909c; --line:#e5e6eb; --brand:#3370ff; --danger:#f53f3f; --warn:#ff7d00; }
  * { box-sizing: border-box; }
  body { margin:0; padding:36px 44px 60px; font:14px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif; color:var(--ink); background:#fff; }
  h1 { font-size:24px; margin:0 0 6px; letter-spacing:-.3px; }
  h2 { font-size:15px; margin:34px 0 10px; padding-left:9px; border-left:3px solid var(--brand); }
  .meta { color:var(--ink3); font-size:12px; }
  .cards { display:flex; flex-wrap:wrap; gap:10px; margin-top:18px; }
  .card { border:1px solid var(--line); border-radius:8px; padding:12px 16px; min-width:132px; }
  .card b { display:block; font-size:22px; font-family:ui-monospace,Consolas,monospace; }
  .card span { color:var(--ink3); font-size:12px; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th, td { text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--ink2); font-weight:600; background:#f7f8fa; }
  td.mono, th.mono { font-family:ui-monospace,Consolas,monospace; }
  .tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; background:#f2f3f5; color:var(--ink2); margin-right:4px; }
  .tag.danger { background:#ffece8; color:var(--danger); }
  .tag.warn { background:#fff7e8; color:var(--warn); }
  .empty { color:var(--ink3); font-size:13px; padding:8px 0; }
  footer { margin-top:44px; padding-top:14px; border-top:1px solid var(--line); color:var(--ink3); font-size:11.5px; }
  @media print {
    body { padding:0; }
    h2 { break-after:avoid; }
    tr, .card { break-inside:avoid; }
    thead { display:table-header-group; }
  }
</style>
</head>
<body>
<h1>资产测绘报告</h1>
<div class="meta">
  StarMap 星图 {{.Version}} · 生成于 {{fmtTime .Generated}} · 统计窗口：最近 {{.Days}} 天（{{fmtDate .Since}} 起）
</div>

<div class="cards">
  <div class="card"><b>{{.Nodes}}</b><span>拓扑节点</span></div>
  <div class="card"><b>{{.Edges}}</b><span>拓扑边</span></div>
  <div class="card"><b>{{.Assets}}</b><span>主机资产</span></div>
  <div class="card"><b>{{.Ports}}</b><span>端口记录</span></div>
  <div class="card"><b>{{.Sites.Total}}</b><span>站点</span></div>
  <div class="card"><b>{{.Events}}</b><span>风险事件（待复核 {{.Pending}}）</span></div>
</div>

<h2>站点风险</h2>
{{if .Expiring}}
<table>
  <thead><tr><th class="mono">站点</th><th>标题</th><th class="mono">证书到期</th><th>剩余</th><th>签发者</th></tr></thead>
  <tbody>
  {{range .Expiring}}
    <tr>
      <td class="mono">{{.Key}}</td>
      <td>{{if .Title}}{{.Title}}{{else}}<span class="empty">（无标题）</span>{{end}}</td>
      <td class="mono">{{.CertExpiry}}</td>
      <td>{{if lt .CertDaysLeft 0}}<span class="tag danger">已过期</span>{{else}}<span class="tag warn">{{.CertDaysLeft}} 天</span>{{end}}</td>
      <td>{{.CertIssuer}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">窗口内没有即将到期或已过期的证书。</div>
{{end}}

<h2>未标注站点（可能对应账外业务系统）</h2>
{{if .Untagged}}
<table>
  <thead><tr><th class="mono">站点</th><th>标题</th><th>产品</th><th class="mono">最后发现</th></tr></thead>
  <tbody>
  {{range .Untagged}}
    <tr>
      <td class="mono">{{.Key}}</td>
      <td>{{if .Title}}{{.Title}}{{else}}<span class="empty">（无标题）</span>{{end}}</td>
      <td>{{.Product}}{{if .Version}} {{.Version}}{{end}}</td>
      <td class="mono">{{fmtTime .LastSeen}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">所有站点都已标注——要么全部登记完毕，要么站点还没被扫出来。</div>
{{end}}

<h2>窗口内站点变更</h2>
<table>
  <thead><tr><th class="mono">站点</th><th>标题</th><th>变更</th><th class="mono">时间</th></tr></thead>
  <tbody>
  {{range .Added}}
    <tr><td class="mono">{{.Key}}</td><td>{{.Title}}</td><td><span class="tag">新增</span></td><td class="mono">{{fmtTime .FirstSeen}}</td></tr>
  {{end}}
  {{range .Removed}}
    <tr><td class="mono">{{.Key}}</td><td>{{.Title}}</td><td><span class="tag danger">不再活动</span></td><td class="mono">{{fmtTime .LastSeen}}</td></tr>
  {{end}}
  {{if and (not .Added) (not .Removed)}}
    <tr><td colspan="4" class="empty">窗口内没有站点变化。</td></tr>
  {{end}}
  </tbody>
</table>

<footer>
  本报告由 StarMap 星图自动生成，数据来源为被动流量观测与主动发现结果的汇总。
  「不再活动」按端口最后观测时间判定，不代表设备已经下线（可能是关机、断网或换了地址）。
  风险标签仅为特征提示，不作违规定性。
</footer>
</body>
</html>`

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"fmtDate": func(t time.Time) string { return t.Local().Format("2006-01-02") },
}).Parse(reportHTML))

// reportRiskLimit 报表里"站点风险"与"未标注站点"两张清单各自的条数上限。
//
// 报表是交出去的产物：50 行覆盖不了全量，但足够让人看清"最要紧的是哪几台"。
// 要全量走 CSV。
const reportRiskLimit = 50

// report GET /api/report?days=7
func (s *Server) report(c *gin.Context) {
	days := 7
	if v := c.Query("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	now := time.Now()
	since := now.AddDate(0, 0, -days)

	snap := s.d.Engine.Snapshot()
	data := &reportData{
		Version:   version.Version,
		Generated: now,
		Days:      days,
		Since:     since,
		Nodes:     snap.Stats.NodeCount,
		Edges:     snap.Stats.EdgeCount,
	}

	if st, err := s.d.Store.SiteStats(store.SiteFilter{}); err == nil {
		data.Sites = st
	} else {
		data.Sites = &model.SiteStats{}
	}
	if n, err := s.d.Store.CountAssets(store.AssetFilter{}); err == nil {
		data.Assets = n
	}
	if n, err := s.d.Store.CountPorts(store.PortFilter{}); err == nil {
		data.Ports = n
	}
	if n, err := s.d.Store.CountEvents(store.EventFilter{}); err == nil {
		data.Events = n
	}
	if n, err := s.d.Store.CountEvents(store.EventFilter{Status: model.EventStatusPending}); err == nil {
		data.Pending = n
	}

	// 清单都限 50 条：报表是给人读的，一份 2000 行的报表等于没有。
	// 需要全量就去导 CSV，两个入口各司其职。
	//
	// "证书风险"是一张表、一个 50 条的上限，所以已过期的先放（更紧急），
	// 再用即将到期的补足——分两次各查 50 条拼起来的话，这一节会有 100 行，
	// 与上面那条"限 50"的承诺不符，而且紧急的过期证书可能被挤到第二页。
	if list, err := s.d.Store.ListSites(store.SiteFilter{OnlyExpired: true}, reportRiskLimit, 0); err == nil {
		data.Expiring = list
	}
	if rest := reportRiskLimit - len(data.Expiring); rest > 0 {
		if list, err := s.d.Store.ListSites(store.SiteFilter{OnlyExpiring: true}, rest, 0); err == nil {
			data.Expiring = append(data.Expiring, list...)
		}
	}
	if list, err := s.d.Store.ListSites(store.SiteFilter{OnlyUntagged: true}, reportRiskLimit, 0); err == nil {
		data.Untagged = list
	}
	if added, gone, err := s.d.Store.SiteChanges(since, reportRiskLimit); err == nil {
		data.Added, data.Removed = added, gone
	}

	// 报表可能含内网拓扑结构，按"导出"同等对待而不是普通只读页面。
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Content-Disposition",
		fmt.Sprintf(`inline; filename="starmap-report-%s.html"`, now.Format("20060102-1504")))
	c.Header("Cache-Control", "no-store")
	if err := reportTmpl.Execute(c.Writer, data); err != nil {
		// 头已经发出去了，只能中断；此时浏览器会看到一个截断的 HTML。
		// 记日志让排障有抓手（模板错误基本只会出现在改模板的当天）。
		internalError(c, err, "渲染报表失败")
	}
}
