package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// 拓扑布局的前端验证（无浏览器依赖，用 node 执行真实的 topo.js）。
//
// 为什么必须有这层护栏：布局塌缩不会报错，只会让图上"四周一堆白边、设备挤成一小团"。
// 用户看到的是"这图看不清"，而代码里一切正常——这类问题只能靠"默认缩放到底多大"
// 这种可量化的判据卡住。默认缩放到 36% 时没人发现，就是因为没有一个数字在盯着它。
//
// 判据来自真实踩坑：
//   1. 40 个节点分到 3 个探针位置时，旧实现按组纵向堆叠成 1104×1280，
//      而画布是 1132×538 的扁矩形，fit() 只能按高度缩到 36%。
//   2. 组内只有一个节点的层，泳道带却拉成整幅满宽，看着就是一整条空带。
//
// 实现真源仍然是 topo.js 这一份，这里不复制一份 Go 布局去对拍。

const layoutHarness = `
'use strict';
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const win = {};
new Function('window', 'document', src)(win, {});
const T = win.SM.Topo;
if (!T.layout) { console.error('SM.Topo.layout 未导出'); process.exit(3); }

// 造一个和真实环境同形状的世界：3 个探针位置，其中一个位置塞 14 台同层主机
// （真实数据里最长的一排在 A 栋 3 层），另有网关与跨网段的少量节点。
function world() {
  const nodes = [], edges = [];
  let id = 0;
  const host = (loc, tier) => {
    const n = { ID: 'node:' + (++id), IPs: ['10.' + (id % 40) + '.0.' + (id % 250 + 1)],
      MAC: '02:00:00:00:00:' + (id % 250).toString(16).padStart(2, '0'),
      Active: true, Location: loc, Role: 'host', Tier: tier };
    nodes.push(n);
    return n;
  };
  const link = (a, b) => edges.push({ ID: 'e' + a.ID + b.ID, SrcID: a.ID, DstID: b.ID,
    Protocol: 'tcp', Bytes: 1000, Kind: 'flow', Active: true });

  // A 栋 3 层：14 台主机 + 1 台网关（就是那个把一层铺成 1794px 宽的大组）
  const gwA = host('A 栋 3 层', 0);
  for (let i = 0; i < 14; i++) link(host('A 栋 3 层', 2), gwA);

  // 机房 B 区：2 台服务器 + 网关，另有 6 台主机
  const gwB = host('机房 B 区', 0);
  for (let i = 0; i < 8; i++) link(host('机房 B 区', 2), gwB);

  // 无位置：14 台（模拟"探针没报位置"的那部分）
  for (let i = 0; i < 14; i++) {
    const n = { ID: 'node:' + (++id), IPs: ['192.168.9.' + (i + 1)], MAC: '',
      Active: true, Role: 'host' };
    nodes.push(n);
  }
  // 一组里只有一个节点的情况：用来验证"单节点泳道不带满整幅"
  nodes.push({ ID: 'lonely', IPs: ['10.99.0.1'], Active: true, Location: '独栋机房', Role: 'server' });
  return { Nodes: nodes, Edges: edges };
}

function bbox(xy) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  Object.keys(xy).forEach(k => {
    const p = xy[k];
    x0 = Math.min(x0, p.x - 40); x1 = Math.max(x1, p.x + 40);
    y0 = Math.min(y0, p.y - 34); y1 = Math.max(y1, p.y + 62);
  });
  if (!isFinite(x0)) return { w: 1, h: 1 };
  return { w: x1 - x0, h: y1 - y0 };
}

const W = world();
const out = { viewports: {}, checks: {} };

function groupBoxes(g, nodes) {
  const byLoc = {};
  Object.keys(g.xy).forEach(id => {
    const n = nodes.find(x => x.ID === id);
    const key = (n && n.Location) || '';
    const p = g.xy[id];
    const o = byLoc[key] || (byLoc[key] = { x0: Infinity, x1: -Infinity, y0: Infinity, y1: -Infinity });
    o.x0 = Math.min(o.x0, p.x); o.x1 = Math.max(o.x1, p.x);
    o.y0 = Math.min(o.y0, p.y); o.y1 = Math.max(o.y1, p.y);
  });
  return byLoc;
}

// 有多少对位置组"并排在同一行"（纵向区间有重叠）。
// 全是 0 就说明又回到"所有组竖着摞成一列"的老行为。
function sideBySide(byLoc) {
  const ks = Object.keys(byLoc);
  let n = 0;
  for (let i = 0; i < ks.length; i++) {
    for (let j = i + 1; j < ks.length; j++) {
      const a = byLoc[ks[i]], b = byLoc[ks[j]];
      if (Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0) >= 0) n++;
    }
  }
  return n;
}

[[1132, 538], [1600, 900], [820, 980]].forEach(([w, h]) => {
  const g = T.layout(W.Nodes, W.Edges, { w, h });
  const b = bbox(g.xy);
  const byLoc = groupBoxes(g, W.Nodes);
  out.viewports[w + 'x' + h] = {
    w: Math.round(b.w), h: Math.round(b.h),
    fit: Number(Math.min(w / b.w, h / b.h).toFixed(3)),
    bands: g.band.length,
    placed: Object.keys(g.xy).length,
    total: W.Nodes.length,
    side_by_side: sideBySide(byLoc)
  };
});

// 泳道带宽度：单节点组的带子不能拉到整幅宽
{
  const g = T.layout(W.Nodes, W.Edges, { w: 1132, h: 538 });
  const xs = Object.keys(g.xy).map(id => g.xy[id].x);
  out.checks.content_w = Math.round(Math.max(...xs) - Math.min(...xs));
  const lonely = g.band.filter(b => (b.loc || '') === '独栋机房')[0];
  // 带子没设 left/right 时返回 -1（NaN 经 JSON 会变成 null，Go 侧就成了 0，
  // 断言会悄悄放过去——这里必须显式区分"没设"和"很窄"）
  out.checks.lonely_band_w = (lonely && lonely.left !== undefined && lonely.right !== undefined)
    ? Math.round(lonely.right - lonely.left) : -1;
  // 带高：单节点层的带子只该有"一个节点 + 上下留白"那么高（52 + 24 + 16 = 92）
  out.checks.lonely_band_h = (lonely && isFinite(lonely.top)) ? Math.round(lonely.bottom - lonely.top) : -1;
}

// 节点不能重叠：同层间距必须 > 节点宽度（52），否则图标会压在一起
{
  const g = T.layout(W.Nodes, W.Edges, { w: 1132, h: 538 });
  const ids = Object.keys(g.xy);
  let minDx = Infinity, minDy = Infinity, overlapPairs = 0;
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = g.xy[ids[i]], b = g.xy[ids[j]];
      const dx = Math.abs(a.x - b.x), dy = Math.abs(a.y - b.y);
      if (dx < 52 && dy < 52) overlapPairs++;
      if (dy > 1) minDx = Math.min(minDx, dx);
      if (dx > 1) minDy = Math.min(minDy, dy);
    }
  }
  out.checks.overlap_pairs = overlapPairs;
}

// 确定性：同样的输入两次必须完全一致（否则"重新布局"按钮会让图乱跳）
{
  const a = JSON.stringify(T.layout(W.Nodes, W.Edges, { w: 1132, h: 538 }).xy);
  const b = JSON.stringify(T.layout(W.Nodes, W.Edges, { w: 1132, h: 538 }).xy);
  out.checks.deterministic = a === b;
}

// 无位置数据（全部 Location 为空）：必须仍能布局，且退回单组全宽泳道
{
  const flat = W.Nodes.map(n => Object.assign({}, n, { Location: '' }));
  const g = T.layout(flat, W.Edges, { w: 1132, h: 538 });
  out.checks.flat_placed = Object.keys(g.xy).length;
  out.checks.flat_total = flat.length;
  out.checks.flat_has_left = g.band.some(b => b.left !== undefined);
}

// 空输入不能算出 NaN 坐标（NaN 会顺着 bbox 把整幅图变成空白）
{
  const g = T.layout([], [], { w: 1132, h: 538 });
  out.checks.empty_ok = Object.keys(g.xy).length === 0;
}

console.log(JSON.stringify(out));
`

func TestTopoLayoutDoesNotCollapse(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过前端布局验证（topo.js 的真实执行需要 node）")
	}
	src, err := FS.ReadFile("assets/topo.js")
	if err != nil {
		t.Fatalf("读取内嵌 assets/topo.js 失败: %v", err)
	}
	dir := t.TempDir()
	jsPath := filepath.Join(dir, "topo.js")
	if err := os.WriteFile(jsPath, src, 0o644); err != nil {
		t.Fatalf("写临时 topo.js 失败: %v", err)
	}
	hPath := filepath.Join(dir, "layout.js")
	if err := os.WriteFile(hPath, []byte(layoutHarness), 0o644); err != nil {
		t.Fatalf("写 harness 失败: %v", err)
	}
	cmd := exec.Command(node, hPath, jsPath)
	cmd.Dir = dir
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("执行 layout 失败: %v\n%s", err, raw)
	}

	var got struct {
		Viewports map[string]struct {
			W          int     `json:"w"`
			H          int     `json:"h"`
			Fit        float64 `json:"fit"`
			Bands      int     `json:"bands"`
			Placed     int     `json:"placed"`
			Total      int     `json:"total"`
			SideBySide int     `json:"side_by_side"`
		} `json:"viewports"`
		Checks struct {
			ContentW      int  `json:"content_w"`
			LonelyBandW   int  `json:"lonely_band_w"`
			LonelyBandH   int  `json:"lonely_band_h"`
			OverlapPairs  int  `json:"overlap_pairs"`
			Deterministic bool `json:"deterministic"`
			FlatPlaced    int  `json:"flat_placed"`
			FlatTotal     int  `json:"flat_total"`
			FlatHasLeft   bool `json:"flat_has_left"`
			EmptyOK       bool `json:"empty_ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解析 harness 输出失败: %v\n输出: %s", err, raw)
	}

	// 1) 默认缩放：40 个节点 + 4 个位置的常见形状，扁画布下不能塌到"看不清"。
	//    旧实现是 0.36；阈值取 0.55——低于这个数图标上的 IP 就不必看了。
	vp := got.Viewports["1132x538"]
	if vp.Fit < 0.55 {
		t.Errorf("1132x538 画布下默认缩放只有 %.0f%%（内容 %dx%d），回归到「泳道纵向堆叠」了",
			vp.Fit*100, vp.W, vp.H)
	}
	if vp.Placed != vp.Total {
		t.Errorf("有节点没拿到坐标：%d/%d（没坐标的节点在图上直接消失）", vp.Placed, vp.Total)
	}
	// 2) 内容不能比画布还"竖"：扁画布上竖着长的图只能缩到很小
	if vp.H > vp.W && vp.W > 0 {
		t.Errorf("1132x538 的内容是 %dx%d——比画布还竖，说明分组又被纵向堆叠了", vp.W, vp.H)
	}
	// 3) 宽画布上组间必须能并排（4 个组全竖着摞成一列就是旧行为）。
	//    注意不能要求"每块画布都并排"——在扁画布上把每组摊成一行反而更省高度，
	//    这是布局器该自己权衡的事，只要默认缩放够大就行。
	if wide := got.Viewports["1600x900"]; wide.SideBySide < 1 {
		t.Errorf("1600x900 宽画布上 4 个位置组没有任何一对并排（side_by_side=%d），组间仍是纵向堆叠",
			wide.SideBySide)
	}
	// 竖画布（侧栏展开、小窗口）同样不能塌
	if tall := got.Viewports["820x980"]; tall.Fit < 0.55 {
		t.Errorf("820x980 画布下默认缩放只有 %.0f%%（内容 %dx%d）", tall.Fit*100, tall.W, tall.H)
	}
	// 4) 单节点组的泳道带不能拉成整幅宽
	if got.Checks.LonelyBandW < 0 {
		t.Error("「独栋机房」的泳道带没有单独宽度（left/right 未设）——整条带又拉成满幅宽了")
	} else if got.Checks.ContentW > 0 && got.Checks.LonelyBandW > got.Checks.ContentW/2 {
		t.Errorf("只有一个节点的组，泳道带宽 %d 超过内容宽度的一半（%d）——这就是那条「整行空带」",
			got.Checks.LonelyBandW, got.Checks.ContentW)
	}
	// 4b) 单节点泳道的带高不能占满一整行网格（ROW_INNER=118），
	//     否则底部只剩一台设备也要占一整条，看着就是空白。
	if h := got.Checks.LonelyBandH; h <= 0 || h > 100 {
		t.Errorf("单节点泳道带高 %dpx（期望 92px 左右）——带高没按实际行数算", h)
	}
	// 5) 节点不能叠在一起
	if got.Checks.OverlapPairs > 0 {
		t.Errorf("有 %d 对节点重叠（图标会压成一坨）", got.Checks.OverlapPairs)
	}
	// 6) 布局必须确定性：否则"重新布局"会让图随机跳动
	if !got.Checks.Deterministic {
		t.Error("同一份数据两次布局结果不一致——「重新布局」按钮会让图乱跳")
	}
	// 7) 没有位置信息时要退回单组全宽泳道（老行为，不能因为这次改动而坏掉）
	if got.Checks.FlatPlaced != got.Checks.FlatTotal {
		t.Errorf("全无位置的场景有节点没拿到坐标：%d/%d", got.Checks.FlatPlaced, got.Checks.FlatTotal)
	}
	if got.Checks.FlatHasLeft {
		t.Error("单一分组时泳道带应保持全宽（left 不设值），否则一条带上会出现断口")
	}
	// 8) 空输入不产生 NaN 坐标
	if !got.Checks.EmptyOK {
		t.Error("空数据时布局产生了坐标（NaN 会顺着 bbox 把整幅图撑成空白）")
	}
}
