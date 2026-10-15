package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func openTest(t *testing.T) *Store { return openTemp(t) }

func TestAssetCRUD(t *testing.T) {
	st := openTest(t)
	now := time.Now()

	// upsert 未归档资产
	a := &model.Asset{
		NodeKey: "mac:aa:bb:cc:dd:ee:01", IPs: []string{"192.168.1.10"}, MAC: "aa:bb:cc:dd:ee:01",
		Status: model.AssetUnarchived, FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
	id, err := st.UpsertAsset(a)
	if err != nil || id == 0 {
		t.Fatalf("UpsertAsset: id=%d err=%v", id, err)
	}

	// 归档
	if err := st.ArchiveAsset(a.NodeKey, "张三", "研发部", "3F-01", "web-01", "Ubuntu 22.04", "测试机", "admin"); err != nil {
		t.Fatal(err)
	}
	got, err := st.AssetByKey(a.NodeKey)
	if err != nil || got == nil {
		t.Fatal("AssetByKey 应找到资产")
	}
	if got.Status != model.AssetArchived || got.Owner != "张三" || got.Department != "研发部" || got.OS != "Ubuntu 22.04" {
		t.Fatalf("归档字段错误: %+v", got)
	}

	// 列表按状态
	archived, _ := st.ListAssets(model.AssetArchived)
	if len(archived) != 1 {
		t.Fatalf("应 1 条已归档，实际 %d", len(archived))
	}
	unarchived, _ := st.ListAssets(model.AssetUnarchived)
	if len(unarchived) != 0 {
		t.Fatalf("应 0 条未归档，实际 %d", len(unarchived))
	}

	// 维护（不改 status）
	if err := st.UpdateAsset(a.NodeKey, "李四", "运维部", "3F-02", "web-01", "Ubuntu 22.04", "更新"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.AssetByKey(a.NodeKey)
	if got.Owner != "李四" || got.Status != model.AssetArchived {
		t.Fatalf("维护后字段错误: %+v", got)
	}

	// 删除
	if err := st.DeleteAsset(a.NodeKey); err != nil {
		t.Fatal(err)
	}
	got, _ = st.AssetByKey(a.NodeKey)
	if got != nil {
		t.Fatal("删除后应查不到")
	}
}

func TestPortCRUD(t *testing.T) {
	st := openTest(t)
	now := time.Now()

	p := &model.PortRecord{NodeKey: "mac:aa", IP: "192.168.1.10", Port: 22, Proto: "tcp", Service: "ssh", State: "open", Source: model.PortSourceTraffic, FirstSeen: now, LastSeen: now}
	if err := st.UpsertPort(p); err != nil {
		t.Fatal(err)
	}
	// 幂等 upsert：重复写入不报错、不产生重复行
	p.Service = "ssh-updated"
	if err := st.UpsertPort(p); err != nil {
		t.Fatal(err)
	}

	ports, err := st.ListPorts("192.168.1.10", "")
	if err != nil || len(ports) != 1 {
		t.Fatalf("应 1 条端口，实际 %d err=%v", len(ports), err)
	}
	if ports[0].Service != "ssh-updated" {
		t.Fatalf("upsert 未更新 service: %+v", ports[0])
	}

	// 按 node_key 删除
	if n, err := st.DeletePortsByKey("mac:aa"); err != nil || n != 1 {
		t.Fatalf("删除端口: n=%d err=%v", n, err)
	}
	ports, _ = st.ListPorts("192.168.1.10", "")
	if len(ports) != 0 {
		t.Fatal("删除后应无端口")
	}
}

func TestUpsertPortsBatch(t *testing.T) {
	st := openTest(t)
	now := time.Now()
	ps := []model.PortRecord{
		{IP: "10.0.0.1", Port: 80, Proto: "tcp", Service: "http", State: "open", Source: model.PortSourceProbe, FirstSeen: now, LastSeen: now},
		{IP: "10.0.0.1", Port: 443, Proto: "tcp", Service: "https", State: "open", Source: model.PortSourceProbe, FirstSeen: now, LastSeen: now},
		{IP: "10.0.0.2", Port: 22, Proto: "tcp", Service: "ssh", State: "open", Source: model.PortSourceProbe, FirstSeen: now, LastSeen: now},
	}
	if err := st.UpsertPorts(ps); err != nil {
		t.Fatal(err)
	}
	ports, _ := st.ListPorts("10.0.0.1", "")
	if len(ports) != 2 {
		t.Fatalf("10.0.0.1 应 2 条端口，实际 %d", len(ports))
	}
}
