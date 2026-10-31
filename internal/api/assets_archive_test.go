package api

// 资产归档的"静默无效"回归（V1.6 修复）。
//
// 资产行是由 syncAssets 从拓扑懒同步出来的，而 syncAssets 只在 `/api/assets`
// 被访问时才跑。这意味着一个刚发现、还没人打开过资产页的主机，
// 在 assets 表里根本没有行——此时归档的 UPDATE 匹配 0 行并返回 nil。
//
// 表现：接口 200、审计日志有一条正常的 asset_archive、界面刷新后归属还是空。
// 这类"成功但没生效"是最难查的一种：没有任何异常可以顺着查。
//
// 现在归档/维护前会自己确保资产行存在（ensureAssetRow），
// 且存储层对 0 行受影响直接报错，防止这个坑再长回来。

import (
	"net/http"
	"testing"
	"time"
)

// TestArchiveBeforeAnyAssetListCall 没访问过资产页也能归档，且真的写进去了。
func TestArchiveBeforeAnyAssetListCall(t *testing.T) {
	h, _, srv := newTaskRouter(t)

	// 拓扑里有一台主机，但资产库还是空的（从未调用过 /api/assets）
	ip := "10.9.9.9"
	srv.d.Engine.ObserveHost(ip, "aa:bb:cc:dd:ee:01", time.Now())
	n := srv.d.Engine.NodeByIP(ip)
	if n == nil {
		t.Fatal("拓扑里没建出节点，测试前提不成立")
	}
	key := n.NodeKey

	w := doReq(t, h, http.MethodPost, "/api/assets/archive", map[string]string{
		"node_key": key, "owner": "张三", "department": "运维部", "location": "机房A",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("归档失败: %d %s", w.Code, w.Body.String())
	}

	// 关键断言：库里真的变成 archived，且归属信息落盘
	a, err := srv.d.Store.AssetByKey(key)
	if err != nil {
		t.Fatalf("读资产失败: %v", err)
	}
	if a == nil {
		t.Fatal("归档后资产行仍不存在——又回到了「返回 ok 但什么都没做」")
	}
	if a.Status != "archived" {
		t.Fatalf("状态未变更: %q", a.Status)
	}
	if a.Owner != "张三" || a.Department != "运维部" || a.Location != "机房A" {
		t.Fatalf("归属信息未落盘: %+v", a)
	}
}

// TestArchiveUnknownNode404 拓扑里也没有的 node_key 必须 404，不能假装成功。
func TestArchiveUnknownNode404(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodPost, "/api/assets/archive", map[string]string{
		"node_key": "ip:203.0.113.77", "owner": "x",
	}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestUpdateAssetUnknownNode404 维护接口同理。
func TestUpdateAssetUnknownNode404(t *testing.T) {
	h, _, _ := newTaskRouter(t)
	w := doReq(t, h, http.MethodPut, "/api/assets/ip:203.0.113.78",
		map[string]string{"owner": "x"}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestUpdateAssetPersistsAfterSync 已存在的资产改归属要能读回。
func TestUpdateAssetPersistsAfterSync(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	ip := "10.9.9.10"
	srv.d.Engine.ObserveHost(ip, "aa:bb:cc:dd:ee:02", time.Now())
	key := srv.d.Engine.NodeByIP(ip).NodeKey

	if w := doReq(t, h, http.MethodPost, "/api/assets/archive", map[string]string{
		"node_key": key, "owner": "李四",
	}, nil); w.Code != http.StatusOK {
		t.Fatalf("归档失败: %d", w.Code)
	}
	if w := doReq(t, h, http.MethodPut, "/api/assets/"+key,
		map[string]string{"owner": "王五", "description": "=cmd|'/c calc'!A0"}, nil); w.Code != http.StatusOK {
		t.Fatalf("维护失败: %d %s", w.Code, w.Body.String())
	}

	a, err := srv.d.Store.AssetByKey(key)
	if err != nil || a == nil {
		t.Fatalf("读回失败: %v", err)
	}
	if a.Owner != "王五" {
		t.Fatalf("归属未更新: %q", a.Owner)
	}
	if a.Description != "=cmd|'/c calc'!A0" {
		t.Fatalf("备注未落盘（原文应原样保存，转义只发生在导出时）: %q", a.Description)
	}
}
