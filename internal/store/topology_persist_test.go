package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"starmap/internal/model"
)

// legacySchema 模拟 V1.0 老库：nodes 无 node_key 列，edges 无 src_key/dst_key 列。
const legacySchema = `
CREATE TABLE nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ips TEXT NOT NULL DEFAULT '[]',
  mac TEXT NOT NULL DEFAULT '',
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  labels TEXT NOT NULL DEFAULT '[]',
  risk_level TEXT NOT NULL DEFAULT 'none',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_id INTEGER NOT NULL,
  dst_id INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT '',
  bytes INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
`

// TestMigrateLegacyTopologyKeys 升级 V1.0 老库：在线加列 + 回填 node_key/端点幂等键 + 去重。
func TestMigrateLegacyTopologyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	// id=1 有 MAC；id=2 无 MAC（走主 IP）；id=3 空节点（兜底 legacy:<id>）
	if _, err := db.Exec(`INSERT INTO nodes(id,ips,mac,first_seen,last_seen) VALUES(1,'["10.0.0.1"]','AA:BB:CC:DD:EE:01',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(id,ips,mac,first_seen,last_seen) VALUES(2,'["10.0.0.2"]','',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(id,ips,mac,first_seen,last_seen) VALUES(3,'[]','',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	// 同一条链路写入两次（老版本没有幂等键），迁移后应只剩一条
	if _, err := db.Exec(`INSERT INTO edges(src_id,dst_id,protocol,bytes,packets,first_seen,last_seen) VALUES(1,2,'tcp',100,2,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO edges(src_id,dst_id,protocol,bytes,packets,first_seen,last_seen) VALUES(1,2,'tcp',888,9,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	// 指向已不存在节点的悬空边
	if _, err := db.Exec(`INSERT INTO edges(src_id,dst_id,protocol,bytes,packets,first_seen,last_seen) VALUES(1,77,'tcp',1,1,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("老库迁移失败: %v", err)
	}
	defer st.Close()

	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{1: "mac:aa:bb:cc:dd:ee:01", 2: "ip:10.0.0.2", 3: "legacy:3"}
	for _, n := range nodes {
		if want[n.ID] != n.NodeKey {
			t.Fatalf("node_key 回填错误 id=%d got=%q want=%q", n.ID, n.NodeKey, want[n.ID])
		}
	}
	// 幂等索引已建立，重复 upsert 同一 NodeKey 不会增生
	for i := 0; i < 3; i++ {
		if err := st.UpsertNodes([]model.Node{{
			ID: 1, NodeKey: "mac:aa:bb:cc:dd:ee:01", IPs: []string{"10.0.0.1"}, MAC: "aa:bb:cc:dd:ee:01",
			FirstSeen: now, LastSeen: now, RiskLevel: model.RiskNone, Active: true,
		}}); err != nil {
			t.Fatalf("UpsertNodes: %v", err)
		}
	}
	if nodes, err = st.ListNodes(); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("幂等 upsert 后节点数应仍为 3，实际 %d", len(nodes))
	}
	if got, err := st.NodeByKey("ip:10.0.0.2"); err != nil || got == nil || got.ID != 2 {
		t.Fatalf("NodeByKey 应能按稳定 key 反查: %+v err=%v", got, err)
	}

	edges, err := st.ListEdges()
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 2 { // (1,2,tcp) 去重 + 悬空边
		t.Fatalf("历史重复边应被去重，实际 %+v", edges)
	}
}

// TestUpsertNodesEdgesIdempotent 幂等键：同 ” 数据反复 upsert 只产生一行。
func TestUpsertNodesEdgesIdempotent(t *testing.T) {
	st := openTemp(t)
	now := time.Now().UTC().Truncate(time.Second)
	nodes := []model.Node{
		{ID: 11, NodeKey: "mac:11:22:33:44:55:66", IPs: []string{"192.168.1.11"}, MAC: "11:22:33:44:55:66",
			FirstSeen: now, LastSeen: now, RiskLevel: model.RiskNone, Active: true},
		{ID: 12, NodeKey: "ip:192.168.1.12", IPs: []string{"192.168.1.12"},
			FirstSeen: now, LastSeen: now, RiskLevel: model.RiskNone, Active: true},
	}
	edges := []EdgeUpsert{{Edge: model.Edge{
		ID: 21, SrcID: 11, DstID: 12, Protocol: "tcp", Bytes: 100, Packets: 2,
		FirstSeen: now, LastSeen: now, Active: true,
	}, SrcKey: "mac:11:22:33:44:55:66", DstKey: "ip:192.168.1.12"}}
	for i := 0; i < 3; i++ {
		if err := st.UpsertNodes(nodes); err != nil {
			t.Fatalf("UpsertNodes#%d: %v", i, err)
		}
		if err := st.UpsertEdges(edges); err != nil {
			t.Fatalf("UpsertEdges#%d: %v", i, err)
		}
	}
	got, err := st.ListNodes()
	if err != nil || len(got) != 2 {
		t.Fatalf("节点应只有 2 行: %+v err=%v", got, err)
	}
	if got[0].MAC != "11:22:33:44:55:66" || got[1].IPs[0] != "192.168.1.12" {
		t.Fatalf("节点内容不匹配: %+v", got)
	}
	gotEdges, err := st.ListEdges()
	if err != nil || len(gotEdges) != 1 {
		t.Fatalf("边应只有 1 行: %+v err=%v", gotEdges, err)
	}
	if gotEdges[0].ID != 21 || gotEdges[0].Bytes != 100 {
		t.Fatalf("边应保持显式 ID 与最新计数: %+v", gotEdges)
	}
	// 累加流量后再 upsert：走 UPDATE 分支且保持单行
	edges[0].Edge.Bytes = 300
	edges[0].Edge.Packets = 6
	if err := st.UpsertEdges(edges); err != nil {
		t.Fatal(err)
	}
	if gotEdges, err = st.ListEdges(); err != nil || len(gotEdges) != 1 || gotEdges[0].Bytes != 300 || gotEdges[0].Packets != 6 {
		t.Fatalf("边应被就地更新: %+v err=%v", gotEdges, err)
	}
}
