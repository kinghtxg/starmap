package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// 公网折叠规则的前端验证（无浏览器依赖）。
//
// 为什么值得单独测：`foldExternal` 是"标红外置"的**唯一**执行点。它错的方式都很安静——
// 把 Highlight 节点一起折了，图上少了最该看的那台；边合并时漏了 Bytes 累加，
// 界面显示"一条细线"；改了入参没改返回值，展开后数据回不去。
// 这些都不会报错，只会让图看起来"好像没问题"。
//
// 实现真源是 topo.js（前端只有这一份），所以这里**不复制一份 Go 版本**去对拍——
// 两份实现必然分叉，测试通过也不能证明线上对。做法是用 node 直接执行真实的 topo.js，
// 拿它的返回值做断言。没有 node 就跳过（CI 里 node 是可选依赖，不能让它变成硬前提）。

const foldHarness = `
'use strict';
const fs = require('fs');
const path = process.argv[2];
const src = fs.readFileSync(path, 'utf8');
const win = {};                      // topo.js 是 IIFE(window)，这里给它一个假 window
new Function('window', 'document', src)(win, {});
const T = win.SM.Topo;
const CLOUD = T.CLOUD_ID;

const ext = (ip, extra) => Object.assign({
  ID: 'ext:' + ip + '/24', IPs: [ip + '/24'], Type: 'cloud', Role: 'external', Active: true, Bytes: 0
}, extra || {});
const host = (id, ip) => ({ ID: id, IPs: [ip || '10.20.0.10'], Role: 'host', Active: true });
const edge = (s, d, proto, bytes, kind) => ({
  ID: 'e' + s + d + proto, SrcID: s, DstID: d, Protocol: proto, Bytes: bytes, Kind: kind || ''
});

const out = {};

// 1) 基本折叠：三个公网段收进一朵云，名字/成员数/活跃都对
{
  const nodes = [ext('203.0.113.0'), ext('198.51.100.0'), ext('192.0.2.0'), host('node:1')];
  const edges = [edge('node:1', 'ext:203.0.113.0/24', 'tcp', 100, 'flow')];
  const before = JSON.stringify(nodes);
  const r = T.foldExternal(nodes, edges);
  out.basic = {
    cloud_id: r.nodes[r.nodes.length - 1].ID,
    members: r.nodes[r.nodes.length - 1].Members,
    folded_len: r.folded.length,
    kept: r.nodes.filter(n => n.ID !== CLOUD).map(n => n.ID),
    input_untouched: before === JSON.stringify(nodes)
  };
}

// 2) Highlight 节点绝不参与折叠：它是"要你看这里"的唯一表达
{
  const nodes = [
    ext('93.184.216.0', { Highlight: true, Overseas: true }),
    ext('203.0.113.0'),
    host('node:1')
  ];
  const r = T.foldExternal(nodes, []);
  out.highlight = {
    kept: r.nodes.map(n => n.ID).sort(),
    members: r.folded.length
  };
}

// 3) 没有可折的就返回 null（界面上不该出现一朵空的云）
{
  const r = T.foldExternal([host('node:1'), host('node:2')], []);
  out.nothing = { is_null: r === null };
}

// 4) 边合并：不同网段、同向同协议同 kind → 一条，Bytes 累加，_folded 计数
{
  const nodes = [host('node:1'), ext('203.0.113.0'), ext('198.51.100.0')];
  const edges = [
    edge('node:1', 'ext:203.0.113.0/24', 'tcp', 100, 'flow'),
    edge('node:1', 'ext:198.51.100.0/24', 'tcp', 250, 'flow'),
    edge('node:1', 'ext:198.51.100.0/24', 'udp', 7, 'flow'),
    edge('ext:203.0.113.0/24', 'node:1', 'tcp', 5, 'flow')   // 反向：不能和正向合并
  ];
  const r = T.foldExternal(nodes, edges);
  out.merge = {
    edges: r.edges.length,
    tcp_out_bytes: r.edges.filter(e => e.Protocol === 'tcp' && e.SrcID === 'node:1')
      .reduce((a, e) => a + e.Bytes, 0),
    tcp_out_folded: r.edges.filter(e => e.Protocol === 'tcp' && e.SrcID === 'node:1')
      .reduce((a, e) => a + (e._folded || 0), 0)
  };
}

// 5) 两端都在云里的边折叠后没有意义：丢弃，字节单独统计（不能悄悄消失）
{
  const nodes = [host('node:1'), ext('203.0.113.0'), ext('198.51.100.0')];
  const edges = [edge('ext:203.0.113.0/24', 'ext:198.51.100.0/24', 'tcp', 42, 'flow')];
  const r = T.foldExternal(nodes, edges);
  out.selfloop = { edges: r.edges.length, self_bytes: r.selfBytes };
}

console.log(JSON.stringify(out));
`

func TestFoldExternalRules(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过前端折叠规则验证（topo.js 的真实执行需要 node）")
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
	hPath := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(hPath, []byte(foldHarness), 0o644); err != nil {
		t.Fatalf("写 harness 失败: %v", err)
	}

	cmd := exec.Command(node, hPath, jsPath)
	cmd.Dir = dir
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("执行 foldExternal 失败: %v\n%s", err, raw)
	}

	var got struct {
		Basic struct {
			CloudID        string   `json:"cloud_id"`
			Members        int      `json:"members"`
			FoldedLen      int      `json:"folded_len"`
			Kept           []string `json:"kept"`
			InputUntouched bool     `json:"input_untouched"`
		} `json:"basic"`
		Highlight struct {
			Kept    []string `json:"kept"`
			Members int      `json:"members"`
		} `json:"highlight"`
		Nothing struct {
			IsNull bool `json:"is_null"`
		} `json:"nothing"`
		Merge struct {
			Edges        int `json:"edges"`
			TCPOutBytes  int `json:"tcp_out_bytes"`
			TCPOutFolded int `json:"tcp_out_folded"`
		} `json:"merge"`
		SelfLoop struct {
			Edges     int `json:"edges"`
			SelfBytes int `json:"self_bytes"`
		} `json:"selfloop"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解析 harness 输出失败: %v\n输出: %s", err, raw)
	}

	if got.Basic.CloudID != "cloud:internet" {
		t.Errorf("云节点 ID 应为 cloud:internet，实际 %q（点击展开是前端按这个 ID 找节点的）", got.Basic.CloudID)
	}
	if got.Basic.Members != 3 || got.Basic.FoldedLen != 3 {
		t.Errorf("应折叠 3 个公网段，实际 members=%d folded=%d", got.Basic.Members, got.Basic.FoldedLen)
	}
	if len(got.Basic.Kept) != 1 || got.Basic.Kept[0] != "node:1" {
		t.Errorf("折叠后除云节点外应只剩 node:1，实际 %v", got.Basic.Kept)
	}
	if !got.Basic.InputUntouched {
		t.Error("foldExternal 改写了入参 nodes——折叠是视图行为，不能污染原始数据（否则展开恢复不回来）")
	}

	if got.Highlight.Members != 1 {
		t.Errorf("Highlight 节点不应被折叠，应只折 1 个，实际 %d", got.Highlight.Members)
	}
	wantKept := []string{"cloud:internet", "ext:93.184.216.0/24", "node:1"}
	if len(got.Highlight.Kept) != 3 {
		t.Fatalf("标红节点必须留在云外：期望 3 个节点，实际 %v", got.Highlight.Kept)
	}
	for i, w := range wantKept {
		if got.Highlight.Kept[i] != w {
			t.Errorf("折叠后节点集合不符：期望 %v，实际 %v", wantKept, got.Highlight.Kept)
			break
		}
	}

	if !got.Nothing.IsNull {
		t.Error("没有可折叠节点时应返回 null，否则界面上会出现一朵空的云")
	}

	// 4 条边：正向 tcp 合并成 1（100+250=350，_folded=2）、正向 udp 1 条、反向 tcp 1 条
	if got.Merge.Edges != 3 {
		t.Errorf("折叠后应有 3 条边（正向 tcp 合并 / 正向 udp / 反向 tcp），实际 %d", got.Merge.Edges)
	}
	if got.Merge.TCPOutBytes != 350 || got.Merge.TCPOutFolded != 2 {
		t.Errorf("tcp 出向边应合并 2 条、字节 350，实际 _folded=%d bytes=%d",
			got.Merge.TCPOutFolded, got.Merge.TCPOutBytes)
	}

	if got.SelfLoop.Edges != 0 || got.SelfLoop.SelfBytes != 42 {
		t.Errorf("云内互连边应被丢弃且字节单独统计，实际 edges=%d selfBytes=%d",
			got.SelfLoop.Edges, got.SelfLoop.SelfBytes)
	}
}
