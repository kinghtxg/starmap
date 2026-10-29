package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 端口展示函数的前端验证。
//
// 为什么值得单独测：这两个函数吃的是后端 model.PortUse 的 JSON，字段名是小写
// （port/proto/sessions/peers/bytes）。写成 p.Port 不会报错，只会在界面上显示
// "undefined" —— 开发时命中的是我已经踩过的那个坑，靠肉眼看截图才发现。
// 这类"静默降级成 undefined"的错误，只有断言才能长期拦住。

const portUIHarness = `
'use strict';
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const start = html.indexOf('/* ---------- 端口展示 ---------- */');
const end = html.indexOf('/* ---------- 节点详情 ---------- */');
if (start < 0 || end < 0 || end <= start) {
  console.error('找不到端口展示代码段，index.html 的结构可能被改动');
  process.exit(3);
}
const src = html.slice(start, end);
// 最小的 UI 桩：只提供这两个函数用到的两个方法
const UI = {
  esc: (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;'),
  fmtBytes: (b) => (b >= 1024 ? (b / 1024).toFixed(1) + ' KB' : b + ' B')
};
const fn = new Function('UI', src + '; return { portBrief, portTableHTML };');
const { portBrief, portTableHTML } = fn(UI);

const list = [
  { port: 443, proto: 'tcp', sessions: 12, peers: 3, bytes: 7280 },
  { port: 8080, proto: 'tcp', sessions: 1, peers: 1, bytes: 100 },
  { port: 7000, sessions: 2, peers: 1, bytes: 2048 }
];

console.log(JSON.stringify({
  brief: portBrief(list),
  brief_empty: portBrief([]),
  brief_null: portBrief(null),
  table: portTableHTML(list, '无'),
  table_empty: portTableHTML([], '未观测到入向会话')
}));
`

func TestPortUIHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过前端端口展示验证")
	}
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatalf("读取内嵌 index.html 失败: %v", err)
	}
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "index.html")
	if err := os.WriteFile(htmlPath, html, 0o644); err != nil {
		t.Fatalf("写临时 index.html 失败: %v", err)
	}
	hPath := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(hPath, []byte(portUIHarness), 0o644); err != nil {
		t.Fatalf("写 harness 失败: %v", err)
	}

	out, err := exec.Command(node, hPath, htmlPath).CombinedOutput()
	if err != nil {
		t.Fatalf("执行端口展示函数失败: %v\n%s", err, out)
	}
	var got struct {
		Brief      string `json:"brief"`
		BriefEmpty string `json:"brief_empty"`
		BriefNull  string `json:"brief_null"`
		Table      string `json:"table"`
		TableEmpty string `json:"table_empty"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("解析输出失败: %v\n%s", err, out)
	}

	if strings.Contains(got.Brief, "undefined") || strings.Contains(got.Table, "undefined") {
		t.Fatalf("界面里出现了 undefined——后端 PortUse 的 JSON 键是小写，前端写成了 PascalCase：\n%s\n%s",
			got.Brief, got.Table)
	}
	if !strings.Contains(got.Brief, "443") || !strings.Contains(got.Brief, "https") {
		t.Errorf("悬浮卡摘要应带端口号与常见用途，实际 %q", got.Brief)
	}
	if !strings.Contains(got.Brief, "×12") {
		t.Errorf("会话数 >1 时应显示次数，实际 %q", got.Brief)
	}
	// 超过 4 个端口时要收敛成 +N，否则悬浮卡会变成一个需要滚动的表格
	// （这个 harness 造了 4 + 3 = 7 个端口，应收敛成 "+3"）
	if !strings.Contains(portBriefOfMany(t, node, hPath, htmlPath), "+3") {
		t.Errorf("端口多于 4 个时应显示「+N」而不是全量铺开")
	}
	if got.BriefEmpty != "" || got.BriefNull != "" {
		t.Errorf("空/空指针输入应返回空串，实际 %q / %q", got.BriefEmpty, got.BriefNull)
	}
	if !strings.Contains(got.Table, "443") || !strings.Contains(got.Table, "tcp") ||
		!strings.Contains(got.Table, "12 次") {
		t.Errorf("详情清单应显示端口、协议与会话数，实际 %q", got.Table)
	}
	if !strings.Contains(got.TableEmpty, "未观测到入向会话") {
		t.Errorf("空清单应显示占位文案，实际 %q", got.TableEmpty)
	}
	if !strings.Contains(got.Table, "7.1 KB") {
		t.Errorf("详情清单应显示流量，实际 %q", got.Table)
	}
}

// portBriefOfMany 用 5 个端口再跑一次，验证「+N」收敛。
func portBriefOfMany(t *testing.T, node, hPath, htmlPath string) string {
	t.Helper()
	script := strings.Replace(portUIHarness,
		"const list = [",
		"const list = [\n  { port: 1 }, { port: 2 }, { port: 3 }, { port: 4 },\n", 1)
	tmp := filepath.Join(t.TempDir(), "many.js")
	if err := os.WriteFile(tmp, []byte(script), 0o644); err != nil {
		t.Fatalf("写 harness 失败: %v", err)
	}
	out, err := exec.Command(node, tmp, htmlPath).CombinedOutput()
	if err != nil {
		t.Fatalf("执行失败: %v\n%s", err, out)
	}
	var got struct {
		Brief string `json:"brief"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("解析输出失败: %v\n%s", err, out)
	}
	return got.Brief
}
