package store

// 会话历史表的幂等与保留期测试（V1.5.2 新增）。
//
// 背景：sessions 表原先既没有唯一键、也没有任何删除路径。
//   - 去重靠聚合器进程内的 emitted 标记 → 重启后仍在活跃的会话被当成"首次"再插一行；
//   - 全仓没有一条 DELETE 碰过这张表 → 现场实测 3 天 60 万行 / 148MB，一年约 18GB。
// 这两条叠起来，被动环境里它就是全库唯一"只进不出"的表。

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"starmap/internal/model"
)

func mkSession(srcPort uint16) *model.Session {
	ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	return &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", SrcPort: srcPort, DstPort: 443, Proto: "tcp"},
		MAC:       "aa:bb:cc:dd:ee:ff", StartTTL: 64,
		FirstSeen: ts, LastSeen: ts,
		BytesUp: 100, BytesDown: 200, Packets: 3,
	}
}

func countSessions(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(1) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("统计会话行数失败: %v", err)
	}
	return n
}

// TestSaveSessionIdempotent 同一个五元组重复写入只能有一行。
// 这正是"重启一次、活跃会话在库里多一份"的根因所在。
func TestSaveSessionIdempotent(t *testing.T) {
	st := openTemp(t)
	ses := mkSession(5000)

	if _, err := st.SaveSession(ses); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	// 模拟重启后再次"首次见到"同一条会话
	if _, err := st.SaveSession(ses); err != nil {
		t.Fatalf("重复写入应幂等，实际报错: %v", err)
	}
	ses.BytesUp = 999
	if _, err := st.SaveSession(ses); err != nil {
		t.Fatalf("再次写入失败: %v", err)
	}

	if n := countSessions(t, st); n != 1 {
		t.Fatalf("同一五元组应有 1 行，实际 %d 行——重启后复用旧口径会再次撑爆这张表", n)
	}
	list, err := st.ListSessions()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions: %v, len=%d", err, len(list))
	}
	if list[0].BytesUp != 999 {
		t.Fatalf("行应随会话演进到最新值，实际 bytes_up=%d", list[0].BytesUp)
	}
}

// TestSaveSessionDoesNotEraseEvidence 后续写入不能把先解析到的证据洗掉。
// keep-alive 连接后续报文里通常没有 ClientHello / HTTP 头，直接覆盖会让 SNI 和
// Host 变成空串——那等于把最有价值的识别线索丢了。
func TestSaveSessionDoesNotEraseEvidence(t *testing.T) {
	st := openTemp(t)

	first := mkSession(5001)
	first.SNI = "oa.example.com"
	first.HTTPHost = "oa.example.com"
	first.JA3 = "ja3hash"
	first.IsLongConn = true
	if _, err := st.SaveSession(first); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	// 后续上报：只有字节增量，识别字段全空
	second := mkSession(5001)
	second.BytesUp = 5000
	if _, err := st.SaveSession(second); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	list, err := st.ListSessions()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions: %v len=%d", err, len(list))
	}
	got := list[0]
	if got.SNI != "oa.example.com" || got.HTTPHost != "oa.example.com" || got.JA3 != "ja3hash" {
		t.Fatalf("识别字段被空值覆盖: sni=%q host=%q ja3=%q", got.SNI, got.HTTPHost, got.JA3)
	}
	if !got.IsLongConn {
		t.Fatal("is_long_conn 只应置位、不应被清回 false")
	}
	if got.BytesUp != 5000 {
		t.Fatalf("字节数应更新为最新值，实际 %d", got.BytesUp)
	}
}

// TestDeleteSessionsBefore 保留期清理。
func TestDeleteSessionsBefore(t *testing.T) {
	st := openTemp(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		s := mkSession(uint16(6000 + i))
		s.FirstSeen, s.LastSeen = old, old
		if _, err := st.SaveSession(s); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		s := mkSession(uint16(7000 + i))
		s.FirstSeen, s.LastSeen = recent, recent
		if _, err := st.SaveSession(s); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}

	n, err := st.DeleteSessionsBefore(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 5 {
		t.Fatalf("应删除 5 条过期会话，实际 %d", n)
	}
	if left := countSessions(t, st); left != 3 {
		t.Fatalf("应剩下 3 条，实际 %d", left)
	}

	// 保留期为 0（不清）时调用方不会调这个函数；这里只验证传未来时间能把表清空
	if _, err := st.DeleteSessionsBefore(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if left := countSessions(t, st); left != 0 {
		t.Fatalf("应清空，实际剩 %d", left)
	}
}

// TestMigrateSessionUniqueDedupesLegacyDB 历史库升级：先有重复行，再建唯一索引。
//
// 这一步必须能过，否则真实环境（跑了 70 小时、60 万行、含重复）升级时
// CREATE UNIQUE INDEX 会直接失败，服务起不来。
func TestMigrateSessionUniqueDedupesLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// 用旧 schema（无唯一索引）手工造一个含重复行的库
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开原始库失败: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE sessions (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  five_tuple TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', start_ttl INTEGER NOT NULL DEFAULT 0,
	  first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
	  bytes_up INTEGER NOT NULL DEFAULT 0, bytes_down INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0,
	  sni TEXT NOT NULL DEFAULT '', http_host TEXT NOT NULL DEFAULT '', ja3 TEXT NOT NULL DEFAULT '',
	  ja4 TEXT NOT NULL DEFAULT '', is_long_conn INTEGER NOT NULL DEFAULT 0,
	  heartbeat_interval_ms INTEGER NOT NULL DEFAULT 0, closed INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	ft := `{"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","src_port":5000,"dst_port":443,"proto":"tcp"}`
	ts := "2026-03-01T00:00:00Z"
	for i := 0; i < 4; i++ { // 同一五元组 4 行（两次重启就能造出来）
		if _, err := raw.Exec(`INSERT INTO sessions(five_tuple,first_seen,last_seen) VALUES(?,?,?)`, ft, ts, ts); err != nil {
			t.Fatalf("插入重复行失败: %v", err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO sessions(five_tuple,first_seen,last_seen) VALUES(?,?,?)`,
		`{"src_ip":"10.0.0.2","dst_ip":"1.1.1.1","src_port":5001,"dst_port":443,"proto":"tcp"}`, ts, ts); err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	_ = raw.Close()

	// 走正常打开流程 → 应自动去重并建唯一索引
	st, err := Open(path)
	if err != nil {
		t.Fatalf("升级历史库失败: %v", err)
	}
	defer st.Close()

	if n := countSessions(t, st); n != 2 {
		t.Fatalf("去重后应剩 2 行（每个五元组 1 行），实际 %d", n)
	}

	// 唯一索引生效：再插同一五元组不会新增行
	ses := mkSession(5000)
	if _, err := st.SaveSession(ses); err != nil {
		t.Fatalf("升级后写入失败: %v", err)
	}
	if n := countSessions(t, st); n != 2 {
		t.Fatalf("唯一索引未生效：写入后变成 %d 行", n)
	}

	// 重复打开必须幂等（迁移不能每次启动都跑一遍 DELETE）
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("二次打开失败: %v", err)
	}
	defer st2.Close()
	if n := countSessions(t, st2); n != 2 {
		t.Fatalf("二次打开后行数变化: %d", n)
	}
}

// TestSaveSessionsBatchMatchesSingle 批量写入必须与逐条写入完全等价。
//
// 批量版是为了把「N 次隐式事务」压成「1 次提交」——探针一批上报里几百条新会话，
// 逐条写会把上报接口耗时按行数线性拉长。压成批量后一旦语义漂移（比如
// 漏掉空值保护），就是"数据看着写进去了，证据却被洗掉"这类静默错误。
func TestSaveSessionsBatchMatchesSingle(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	batch := []model.Session{*mkSession(1001), *mkSession(1002), *mkSession(1003)}
	if err := st.SaveSessions(batch); err != nil {
		t.Fatalf("批量写入失败: %v", err)
	}

	// 再走一次单条 upsert：带 SNI 的覆盖应生效，空 SNI 不应洗掉已有值
	withSNI := mkSession(1001)
	withSNI.SNI = "a.example.com"
	if _, err := st.SaveSession(withSNI); err != nil {
		t.Fatal(err)
	}
	emptySNI := mkSession(1001)
	emptySNI.BytesUp = 999
	if _, err := st.SaveSession(emptySNI); err != nil {
		t.Fatal(err)
	}

	all, err := st.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("应只有 3 行（唯一键去重），实际 %d 行", len(all))
	}
	for _, s := range all {
		if s.FiveTuple.SrcPort != 1001 {
			continue
		}
		if s.SNI != "a.example.com" {
			t.Fatalf("空 SNI 不应覆盖已有证据，实际 %q", s.SNI)
		}
		if s.BytesUp != 999 {
			t.Fatalf("字节数应被更新为 999，实际 %d", s.BytesUp)
		}
		return
	}
	t.Fatal("未找到 1001 号会话")
}

// TestSaveSessionsEmpty batch 为空时不得开事务、不得报错。
func TestSaveSessionsEmpty(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveSessions(nil); err != nil {
		t.Fatalf("空批量应直接返回 nil，实际 %v", err)
	}
}
