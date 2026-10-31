package store

// 资产批量同步的语义测试（V1.5.2 新增）。
//
// syncAssets 原先是"逐节点 SELECT + UPSERT"，V1.5.2 改成一次事务里的批量 upsert。
// 改写最容易踩的坑是语义漂移，尤其是**已归档资产的人工信息不能被自动同步覆盖**：
// 用户填的归属人、部门、物理位置是这个模块唯一的不可再生数据。

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func node(key, mac string, ips []string, loc string) model.Node {
	ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	return model.Node{NodeKey: key, MAC: mac, IPs: ips, Location: loc, FirstSeen: ts, LastSeen: ts}
}

func TestSyncAssetsFromNodesCreatesUnarchived(t *testing.T) {
	st := openTemp(t)
	now := time.Now()

	nodes := []model.Node{
		node("mac:aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:01", []string{"10.0.0.1"}, "机房A"),
		node("mac:aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:02", []string{"10.0.0.2"}, ""),
		node("", "", []string{"10.0.0.3"}, ""), // 无稳定键：跳过
	}
	n, err := st.SyncAssetsFromNodes(nodes, now)
	if err != nil {
		t.Fatalf("批量同步失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("应写入 2 条（跳过无 node_key 的），实际 %d", n)
	}

	a, err := st.AssetByKey("mac:aa:aa:aa:aa:aa:01")
	if err != nil || a == nil {
		t.Fatalf("AssetByKey: %v", err)
	}
	if a.Status != model.AssetUnarchived {
		t.Fatalf("新同步的资产应为 unarchived，实际 %q", a.Status)
	}
	if a.Location != "机房A" {
		t.Fatalf("未归档资产应跟随探针位置，实际 %q", a.Location)
	}
}

func TestSyncAssetsFromNodesPreservesArchivedFields(t *testing.T) {
	st := openTemp(t)
	now := time.Now()

	// 先建一条并归档，填上人工信息
	if _, err := st.SyncAssetsFromNodes([]model.Node{
		node("mac:bb:bb:bb:bb:bb:01", "bb:bb:bb:bb:bb:01", []string{"10.0.0.9"}, "机房A"),
	}, now); err != nil {
		t.Fatalf("初次同步失败: %v", err)
	}
	if err := st.ArchiveAsset("mac:bb:bb:bb:bb:bb:01", "老张", "财务部", "3F-302", "cw-pc", "Windows 10", "备注", "admin"); err != nil {
		t.Fatalf("归档失败: %v", err)
	}

	// 再来一轮同步：IP 变了、探针位置变了
	if _, err := st.SyncAssetsFromNodes([]model.Node{
		node("mac:bb:bb:bb:bb:bb:01", "bb:bb:bb:bb:bb:01", []string{"10.0.0.10"}, "机房B"),
	}, now.Add(time.Minute)); err != nil {
		t.Fatalf("再次同步失败: %v", err)
	}

	a, err := st.AssetByKey("mac:bb:bb:bb:bb:bb:01")
	if err != nil || a == nil {
		t.Fatalf("AssetByKey: %v", err)
	}
	if a.Owner != "老张" || a.Department != "财务部" || a.Hostname != "cw-pc" || a.OS != "Windows 10" {
		t.Fatalf("已归档资产的人工信息被自动同步覆盖: owner=%q dept=%q host=%q os=%q",
			a.Owner, a.Department, a.Hostname, a.OS)
	}
	if a.Location != "3F-302" {
		t.Fatalf("已归档资产的物理位置被探针位置覆盖: %q", a.Location)
	}
	if a.Status != model.AssetArchived {
		t.Fatalf("归档状态被改回 %q", a.Status)
	}
	// 观测类字段应当刷新
	if len(a.IPs) != 1 || a.IPs[0] != "10.0.0.10" {
		t.Fatalf("IP 应刷新为最新观测值，实际 %v", a.IPs)
	}
}

func TestSyncAssetsFromNodesIdempotent(t *testing.T) {
	st := openTemp(t)
	now := time.Now()
	nodes := []model.Node{
		node("mac:cc:cc:cc:cc:cc:01", "cc:cc:cc:cc:cc:01", []string{"10.0.0.20"}, ""),
		node("mac:cc:cc:cc:cc:cc:02", "cc:cc:cc:cc:cc:02", []string{"10.0.0.21"}, ""),
	}
	for i := 0; i < 3; i++ {
		if _, err := st.SyncAssetsFromNodes(nodes, now); err != nil {
			t.Fatalf("第 %d 轮同步失败: %v", i, err)
		}
	}
	list, err := st.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("重复同步不应产生新行，实际 %d 条", len(list))
	}
}
