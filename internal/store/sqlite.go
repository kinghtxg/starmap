// Package store 提供 SQLite 持久化（modernc.org/sqlite 纯 Go 驱动，免 CGO）。
// 建表 schema：nodes, edges, sessions, events, whitelist, domains, audit, config。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动

	"starmap/internal/model"
)

// Store 数据库访问对象
type Store struct {
	db *sql.DB
}

// schema 建表语句
const schema = `
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_key TEXT NOT NULL DEFAULT '',
  ips TEXT NOT NULL DEFAULT '[]',
  mac TEXT NOT NULL DEFAULT '',
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  labels TEXT NOT NULL DEFAULT '[]',
  risk_level TEXT NOT NULL DEFAULT 'none',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_id INTEGER NOT NULL,
  dst_id INTEGER NOT NULL,
  src_key TEXT NOT NULL DEFAULT '',
  dst_key TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL DEFAULT '',
  bytes INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  five_tuple TEXT NOT NULL,
  mac TEXT NOT NULL DEFAULT '',
  start_ttl INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  bytes_up INTEGER NOT NULL DEFAULT 0,
  bytes_down INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  sni TEXT NOT NULL DEFAULT '',
  http_host TEXT NOT NULL DEFAULT '',
  ja3 TEXT NOT NULL DEFAULT '',
  ja4 TEXT NOT NULL DEFAULT '',
  is_long_conn INTEGER NOT NULL DEFAULT 0,
  heartbeat_interval_ms INTEGER NOT NULL DEFAULT 0,
  closed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  node_id INTEGER NOT NULL DEFAULT 0,
  title TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',
  level TEXT NOT NULL DEFAULT 'mid',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  review_note TEXT NOT NULL DEFAULT '',
  reviewer TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS whitelist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  cidrs TEXT NOT NULL DEFAULT '[]',
  color TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_key TEXT NOT NULL UNIQUE,
  ips TEXT NOT NULL DEFAULT '[]',
  mac TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unarchived',
  owner TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  archived_at DATETIME,
  archived_by TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_key TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL DEFAULT 'tcp',
  service TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'open',
  source TEXT NOT NULL DEFAULT 'traffic',
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_key ON ports(node_key, ip, port, proto);
CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
`

// Open 打开（不存在则创建）SQLite 数据库并建表。
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// SQLite 单写者，限制连接数避免 database is locked
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("设置 WAL 失败: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("建表失败: %w", err)
	}
	// P0-2：V1.0 库无 node_key/src_key/dst_key 列，需在线扩容并回填后才能建立幂等索引
	if err := migrateTopologyKeys(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("拓扑持久化迁移失败: %w", err)
	}
	return &Store{db: db}, nil
}

// ---------- 拓扑持久化迁移（P0-2） ----------

// 节点/边的稳定键索引：nodes.node_key 唯一；edge 以 (src_key,dst_key,protocol) 为幂等键。
// 空 node_key 的历史脏行用偏斜部分索引豁免（ALTER 前建的表可能留下空串，且不止一行）。
const topologyKeyIndex = `
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_node_key ON nodes(node_key) WHERE node_key <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_endpoints ON edges(src_key,dst_key,protocol);
`

func migrateTopologyKeys(db *sql.DB) error {
	if err := ensureColumn(db, "nodes", "node_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "edges", "src_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "edges", "dst_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := backfillNodeKeys(db); err != nil {
		return err
	}
	if err := backfillEdgeKeys(db); err != nil {
		return err
	}
	_, err := db.Exec(topologyKeyIndex)
	return err
}

func ensureColumn(db *sql.DB, table, col, decl string) error {
	var exists int
	// table/col 均为本包常量，不存在外部输入拼接风险
	err := db.QueryRow(fmt.Sprintf(
		`SELECT COUNT(1) FROM pragma_table_info('%s') WHERE name='%s'`, table, col)).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	_, err = db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, col, decl))
	return err
}

// backfillNodeKeys 给历史节点补齐 node_key（优先 MAC，无 MAC 用主 IP）。
// 无法推导身份的节点（无 MAC 且无 IP）用 legacy:<id> 兜底；重复身份用 #<id> 后缀去重，
// 保证 node_key 唯一，后续幂等 upsert 才不会相互覆盖。
func backfillNodeKeys(db *sql.DB) error {
	used := map[string]bool{}
	if rows, err := db.Query(`SELECT node_key FROM nodes WHERE node_key <> ''`); err == nil {
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return err
			}
			used[k] = true
		}
		rows.Close()
	} else {
		return err
	}
	rows, err := db.Query(`SELECT id,ips,mac FROM nodes WHERE node_key='' ORDER BY id`)
	if err != nil {
		return err
	}
	var pending []struct {
		id  int64
		key string
	}
	for rows.Next() {
		var id int64
		var ips, mac string
		if err := rows.Scan(&id, &ips, &mac); err != nil {
			rows.Close()
			return err
		}
		var list []string
		fromJSON(ips, &list)
		key := deriveNodeKey(mac, list)
		if key == "" {
			key = fmt.Sprintf("legacy:%d", id)
		}
		if used[key] {
			key = fmt.Sprintf("%s#%d", key, id)
		}
		used[key] = true
		pending = append(pending, struct {
			id  int64
			key string
		}{id, key})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, p := range pending {
		if _, err := tx.Exec(`UPDATE nodes SET node_key=? WHERE id=?`, p.key, p.id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// backfillEdgeKeys 用节点 node_key 回填边的两端，并清掉历史重复边
// （同 (src_key,dst_key,protocol) 保留最小 id），否则幂等索引建不起来。
func backfillEdgeKeys(db *sql.DB) error {
	keyByID := map[int64]string{}
	rows, err := db.Query(`SELECT id,node_key FROM nodes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var k string
		if err := rows.Scan(&id, &k); err != nil {
			rows.Close()
			return err
		}
		keyByID[id] = k
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type edgeRow struct {
		id     int64
		srcID  int64
		dstID  int64
		srcKey string
		dstKey string
	}
	rows, err = db.Query(`SELECT id,src_id,dst_id,src_key,dst_key FROM edges`)
	if err != nil {
		return err
	}
	var pending []edgeRow
	for rows.Next() {
		var r edgeRow
		if err := rows.Scan(&r.id, &r.srcID, &r.dstID, &r.srcKey, &r.dstKey); err != nil {
			rows.Close()
			return err
		}
		if r.srcKey == "" || r.dstKey == "" {
			// 端点节点已不在库内（历史脏数据）：用 id 兜底保证唯一，不与正常边混叠
			if v, ok := keyByID[r.srcID]; ok && r.srcKey == "" {
				r.srcKey = v
			} else if r.srcKey == "" {
				r.srcKey = fmt.Sprintf("missing:%d", r.srcID)
			}
			if v, ok := keyByID[r.dstID]; ok && r.dstKey == "" {
				r.dstKey = v
			} else if r.dstKey == "" {
				r.dstKey = fmt.Sprintf("missing:%d", r.dstID)
			}
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, r := range pending {
		if _, err := tx.Exec(`UPDATE edges SET src_key=?,dst_key=? WHERE id=?`, r.srcKey, r.dstKey, r.id); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM edges WHERE id NOT IN (SELECT MIN(id) FROM edges GROUP BY src_key,dst_key,protocol)`); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// deriveNodeKey 按 MAC 优先、主 IP 兜底推导稳定节点身份（与 topology.NodeKeyOf 同规则）。
// store 与 topology 分属不同层，此处独立实现以避免 store → topology 的反向依赖。
func deriveNodeKey(mac string, ips []string) string {
	if m := strings.TrimSpace(mac); m != "" {
		return "mac:" + strings.ToLower(m)
	}
	if len(ips) > 0 {
		if ip := strings.TrimSpace(ips[0]); ip != "" {
			return "ip:" + ip
		}
	}
	return ""
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// ---------- 序列化辅助 ----------

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON(data string, v any) {
	if data == "" {
		return
	}
	_ = json.Unmarshal([]byte(data), v)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func i2b(i int) bool { return i != 0 }

// ---------- Node CRUD ----------

// CreateNode 创建节点，返回带 ID 的节点。（NodeKey 为空时按 MAC/IP 推导后一并写入）
func (s *Store) CreateNode(n *model.Node) (int64, error) {
	if n.NodeKey == "" {
		n.NodeKey = deriveNodeKey(n.MAC, n.IPs)
	}
	res, err := s.db.Exec(
		`INSERT INTO nodes(node_key,ips,mac,first_seen,last_seen,domain,labels,risk_level,active) VALUES(?,?,?,?,?,?,?,?,?)`,
		n.NodeKey, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateNode 更新节点全部字段。
func (s *Store) UpdateNode(n *model.Node) error {
	if n.NodeKey == "" {
		n.NodeKey = deriveNodeKey(n.MAC, n.IPs)
	}
	_, err := s.db.Exec(
		`UPDATE nodes SET node_key=?,ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE id=?`,
		n.NodeKey, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.ID)
	return err
}

// UpsertNodes 批量幂等落盘节点（拓扑节流 flush 调用）。
// 先按主键 id 更新覆盖自身历史，未命中再显式带上 id 插入——保证重启恢复后
// 内存中 node.ID 与库内 id、历史事件里的 node_id 三者始终对齐。
func (s *Store) UpsertNodes(ns []model.Node) error {
	if len(ns) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for i := range ns {
		n := &ns[i]
		if n.NodeKey == "" {
			n.NodeKey = deriveNodeKey(n.MAC, n.IPs)
		}
		res, err := tx.Exec(
			`UPDATE nodes SET node_key=?,ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE id=?`,
			n.NodeKey, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
		if aff, err := res.RowsAffected(); err == nil && aff > 0 {
			continue
		}
		_, err = tx.Exec(
			`INSERT INTO nodes(id,node_key,ips,mac,first_seen,last_seen,domain,labels,risk_level,active) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			n.ID, n.NodeKey, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active))
		if err != nil {
			// id 被同名 key 的旧行占用（理论上不会：恢复时已加载全部行）
			// 退化为按 node_key 更新那一行，保持库内不重复。
			if _, err2 := tx.Exec(
				`UPDATE nodes SET ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE node_key=?`,
				toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.NodeKey); err2 != nil {
				tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

// NodeByKey 按稳定 node_key 查询节点（不存在返回 nil）。
func (s *Store) NodeByKey(key string) (*model.Node, error) {
	n, err := scanNode(s.db.QueryRow(nodeColumns+` WHERE node_key=?`, key))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// nodeColumns 节点查询列清单（含 P0-2 新增的稳定 key 列）。
const nodeColumns = `SELECT id,node_key,ips,mac,first_seen,last_seen,domain,labels,risk_level,active FROM nodes`

// GetNode 按 ID 查询节点。
func (s *Store) GetNode(id int64) (*model.Node, error) {
	n, err := scanNode(s.db.QueryRow(nodeColumns+` WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

type rowScanner interface{ Scan(...any) error }

func scanNode(row rowScanner) (*model.Node, error) {
	var n model.Node
	var ips, labels string
	var active int
	err := row.Scan(&n.ID, &n.NodeKey, &ips, &n.MAC, &n.FirstSeen, &n.LastSeen, &n.Domain, &labels, &n.RiskLevel, &active)
	if err != nil {
		return nil, err
	}
	fromJSON(ips, &n.IPs)
	fromJSON(labels, &n.Labels)
	n.Active = i2b(active)
	return &n, nil
}

// ListNodes 查询全部节点。
func (s *Store) ListNodes() ([]model.Node, error) {
	rows, err := s.db.Query(nodeColumns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// DeleteNode 删除节点。
func (s *Store) DeleteNode(id int64) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
	return err
}

// ---------- Edge CRUD ----------

// CreateEdge 创建链路。
func (s *Store) CreateEdge(e *model.Edge) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO edges(src_id,dst_id,protocol,bytes,packets,first_seen,last_seen,active) VALUES(?,?,?,?,?,?,?,?)`,
		e.SrcID, e.DstID, e.Protocol, e.Bytes, e.Packets, e.FirstSeen, e.LastSeen, b2i(e.Active))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EdgeUpsert 边幂等落盘数据：SrcKey/DstKey 为两端节点的稳定 key，
// (src_key,dst_key,protocol) 即边的幂等主键（P0-2）。
type EdgeUpsert struct {
	Edge   model.Edge
	SrcKey string
	DstKey string
}

// UpsertEdges 批量幂等落盘链路（拓扑节流 flush 调用）。
// 同一条链路每次 flush 都走一次 UPDATE，不会像 CreateEdge 那样累积重复行。
func (s *Store) UpsertEdges(es []EdgeUpsert) error {
	if len(es) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for i := range es {
		u := &es[i]
		e := u.Edge
		res, err := tx.Exec(
			`UPDATE edges SET bytes=?,packets=?,first_seen=?,last_seen=?,active=? WHERE src_key=? AND dst_key=? AND protocol=?`,
			e.Bytes, e.Packets, e.FirstSeen, e.LastSeen, b2i(e.Active), u.SrcKey, u.DstKey, e.Protocol)
		if err != nil {
			tx.Rollback()
			return err
		}
		if aff, err := res.RowsAffected(); err == nil && aff > 0 {
			continue
		}
		_, err = tx.Exec(
			`INSERT INTO edges(id,src_id,dst_id,src_key,dst_key,protocol,bytes,packets,first_seen,last_seen,active) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			e.ID, e.SrcID, e.DstID, u.SrcKey, u.DstKey, e.Protocol, e.Bytes, e.Packets, e.FirstSeen, e.LastSeen, b2i(e.Active))
		if err != nil {
			// 幂等键已被别的行占用：退化为忽略本行，下次 flush 会重新覆盖
			continue
		}
	}
	return tx.Commit()
}

// UpdateEdge 更新链路。
func (s *Store) UpdateEdge(e *model.Edge) error {
	_, err := s.db.Exec(
		`UPDATE edges SET src_id=?,dst_id=?,protocol=?,bytes=?,packets=?,first_seen=?,last_seen=?,active=? WHERE id=?`,
		e.SrcID, e.DstID, e.Protocol, e.Bytes, e.Packets, e.FirstSeen, e.LastSeen, b2i(e.Active), e.ID)
	return err
}

func scanEdge(row rowScanner) (*model.Edge, error) {
	var e model.Edge
	var active int
	err := row.Scan(&e.ID, &e.SrcID, &e.DstID, &e.Protocol, &e.Bytes, &e.Packets, &e.FirstSeen, &e.LastSeen, &active)
	if err != nil {
		return nil, err
	}
	e.Active = i2b(active)
	return &e, nil
}

// GetEdge 按 ID 查询链路。
func (s *Store) GetEdge(id int64) (*model.Edge, error) {
	e, err := scanEdge(s.db.QueryRow(`SELECT id,src_id,dst_id,protocol,bytes,packets,first_seen,last_seen,active FROM edges WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// ListEdges 查询全部链路。
func (s *Store) ListEdges() ([]model.Edge, error) {
	rows, err := s.db.Query(`SELECT id,src_id,dst_id,protocol,bytes,packets,first_seen,last_seen,active FROM edges`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Edge
	for rows.Next() {
		e, err := scanEdge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// DeleteEdge 删除链路。
func (s *Store) DeleteEdge(id int64) error {
	_, err := s.db.Exec(`DELETE FROM edges WHERE id=?`, id)
	return err
}

// ---------- Session CRUD ----------

// SaveSession 保存会话（新会话插入，返回 ID）。
func (s *Store) SaveSession(ses *model.Session) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO sessions(five_tuple,mac,start_ttl,first_seen,last_seen,bytes_up,bytes_down,packets,sni,http_host,ja3,ja4,is_long_conn,heartbeat_interval_ms,closed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		toJSON(ses.FiveTuple), ses.MAC, ses.StartTTL, ses.FirstSeen, ses.LastSeen,
		ses.BytesUp, ses.BytesDown, ses.Packets, ses.SNI, ses.HTTPHost, ses.JA3, ses.JA4,
		b2i(ses.IsLongConn), ses.HeartbeatIntervalMs, b2i(ses.Closed))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListSessions 查询全部会话。
func (s *Store) ListSessions() ([]model.Session, error) {
	rows, err := s.db.Query(`SELECT five_tuple,mac,start_ttl,first_seen,last_seen,bytes_up,bytes_down,packets,sni,http_host,ja3,ja4,is_long_conn,heartbeat_interval_ms,closed FROM sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Session
	for rows.Next() {
		var ses model.Session
		var ft string
		var longConn, closed int
		if err := rows.Scan(&ft, &ses.MAC, &ses.StartTTL, &ses.FirstSeen, &ses.LastSeen,
			&ses.BytesUp, &ses.BytesDown, &ses.Packets, &ses.SNI, &ses.HTTPHost, &ses.JA3, &ses.JA4,
			&longConn, &ses.HeartbeatIntervalMs, &closed); err != nil {
			return nil, err
		}
		fromJSON(ft, &ses.FiveTuple)
		ses.IsLongConn = i2b(longConn)
		ses.Closed = i2b(closed)
		out = append(out, ses)
	}
	return out, rows.Err()
}

// ---------- RiskEvent CRUD ----------

// CreateEvent 创建风险事件。
func (s *Store) CreateEvent(e *model.RiskEvent) (int64, error) {
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.Status == "" {
		e.Status = model.EventStatusPending
	}
	res, err := s.db.Exec(
		`INSERT INTO events(type,node_id,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.Type, e.NodeID, e.Title, e.Detail, toJSON(e.Evidence), e.Status, e.Level,
		e.CreatedAt, e.UpdatedAt, e.ReviewNote, e.Reviewer)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateEventStatus 复核操作：更新状态/备注/复核人。
func (s *Store) UpdateEventStatus(id int64, status, note, reviewer string) error {
	_, err := s.db.Exec(`UPDATE events SET status=?,review_note=?,reviewer=?,updated_at=? WHERE id=?`,
		status, note, reviewer, time.Now(), id)
	return err
}

// UpdateEventEvidence 事件去重命中时仅更新证据与 UpdatedAt（SPEC §10.5）。
func (s *Store) UpdateEventEvidence(id int64, evidence map[string]string) error {
	_, err := s.db.Exec(`UPDATE events SET evidence=?,updated_at=? WHERE id=?`,
		toJSON(evidence), time.Now(), id)
	return err
}

func scanEvent(row rowScanner) (*model.RiskEvent, error) {
	var e model.RiskEvent
	var evidence string
	err := row.Scan(&e.ID, &e.Type, &e.NodeID, &e.Title, &e.Detail, &evidence, &e.Status, &e.Level,
		&e.CreatedAt, &e.UpdatedAt, &e.ReviewNote, &e.Reviewer)
	if err != nil {
		return nil, err
	}
	fromJSON(evidence, &e.Evidence)
	return &e, nil
}

// GetEvent 按 ID 查询事件。
func (s *Store) GetEvent(id int64) (*model.RiskEvent, error) {
	e, err := scanEvent(s.db.QueryRow(`SELECT id,type,node_id,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer FROM events WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// ListEvents 按状态/类型筛选查询事件（空串表示不筛选）。
func (s *Store) ListEvents(status, evType string) ([]model.RiskEvent, error) {
	query := `SELECT id,type,node_id,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer FROM events WHERE 1=1`
	var args []any
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	if evType != "" {
		query += ` AND type=?`
		args = append(args, evType)
	}
	query += ` ORDER BY id DESC`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RiskEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// ---------- Whitelist CRUD ----------

// CreateWhitelistEntry 新增白名单条目。
func (s *Store) CreateWhitelistEntry(w *model.WhitelistEntry) (int64, error) {
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO whitelist(kind,value,note,created_at) VALUES(?,?,?,?)`,
		w.Kind, w.Value, w.Note, w.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListWhitelist 查询全部白名单条目。
func (s *Store) ListWhitelist() ([]model.WhitelistEntry, error) {
	rows, err := s.db.Query(`SELECT id,kind,value,note,created_at FROM whitelist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WhitelistEntry
	for rows.Next() {
		var w model.WhitelistEntry
		if err := rows.Scan(&w.ID, &w.Kind, &w.Value, &w.Note, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// UpdateWhitelistEntry 更新白名单条目。
func (s *Store) UpdateWhitelistEntry(w *model.WhitelistEntry) error {
	_, err := s.db.Exec(`UPDATE whitelist SET kind=?,value=?,note=? WHERE id=?`, w.Kind, w.Value, w.Note, w.ID)
	return err
}

// DeleteWhitelistEntry 删除白名单条目。
func (s *Store) DeleteWhitelistEntry(id int64) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE id=?`, id)
	return err
}

// ---------- NetDomain CRUD ----------

// CreateDomain 创建网络域。
func (s *Store) CreateDomain(d *model.NetDomain) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO domains(name,cidrs,color) VALUES(?,?,?)`, d.Name, toJSON(d.CIDRs), d.Color)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanDomain(row rowScanner) (*model.NetDomain, error) {
	var d model.NetDomain
	var cidrs string
	if err := row.Scan(&d.ID, &d.Name, &cidrs, &d.Color); err != nil {
		return nil, err
	}
	fromJSON(cidrs, &d.CIDRs)
	return &d, nil
}

// GetDomain 按 ID 查询网络域。
func (s *Store) GetDomain(id int64) (*model.NetDomain, error) {
	d, err := scanDomain(s.db.QueryRow(`SELECT id,name,cidrs,color FROM domains WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return d, err
}

// ListDomains 查询全部网络域。
func (s *Store) ListDomains() ([]model.NetDomain, error) {
	rows, err := s.db.Query(`SELECT id,name,cidrs,color FROM domains ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.NetDomain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// UpdateDomain 更新网络域。
func (s *Store) UpdateDomain(d *model.NetDomain) error {
	_, err := s.db.Exec(`UPDATE domains SET name=?,cidrs=?,color=? WHERE id=?`, d.Name, toJSON(d.CIDRs), d.Color, d.ID)
	return err
}

// DeleteDomain 删除网络域。
func (s *Store) DeleteDomain(id int64) error {
	_, err := s.db.Exec(`DELETE FROM domains WHERE id=?`, id)
	return err
}

// ---------- Audit ----------

// AddAuditLog 追加审计日志。
func (s *Store) AddAuditLog(a *model.AuditLog) (int64, error) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO audit(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)`,
		a.Actor, a.Action, a.Target, a.Detail, a.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAuditLogs 查询审计日志（倒序，limit<=0 表示不限）。
func (s *Store) ListAuditLogs(limit int) ([]model.AuditLog, error) {
	query := `SELECT id,actor,action,target,detail,created_at FROM audit ORDER BY id DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditLog
	for rows.Next() {
		var a model.AuditLog
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- Config KV ----------

// SetConfigKV 写入系统参数键值。
func (s *Store) SetConfigKV(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// GetConfigKV 读取系统参数键值，不存在返回 ("", nil)。
func (s *Store) GetConfigKV(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// DeleteAuditLogsBefore 清理早于 cutoff 的审计日志（§10.8 保留期），返回删除条数。
func (s *Store) DeleteAuditLogsBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- 主机资产库（V1.2） ----------

const assetColumns = `SELECT id,node_key,ips,mac,hostname,os,status,owner,department,location,description,first_seen,last_seen,archived_at,archived_by,created_at,updated_at FROM assets`

func scanAsset(row rowScanner) (*model.Asset, error) {
	var a model.Asset
	var ips string
	var archivedAt sql.NullTime
	err := row.Scan(&a.ID, &a.NodeKey, &ips, &a.MAC, &a.Hostname, &a.OS, &a.Status, &a.Owner,
		&a.Department, &a.Location, &a.Description, &a.FirstSeen, &a.LastSeen, &archivedAt, &a.ArchivedBy,
		&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	fromJSON(ips, &a.IPs)
	if archivedAt.Valid {
		a.ArchivedAt = archivedAt.Time
	}
	return &a, nil
}

// UpsertAsset 幂等写入/更新资产（按 node_key）。在线状态由调用方计算。
func (s *Store) UpsertAsset(a *model.Asset) (int64, error) {
	ips := toJSON(a.IPs)
	var archivedAt any
	if a.ArchivedAt.IsZero() {
		archivedAt = nil
	} else {
		archivedAt = a.ArchivedAt
	}
	now := time.Now()
	_, err := s.db.Exec(`INSERT INTO assets(node_key,ips,mac,hostname,os,status,owner,department,location,description,first_seen,last_seen,archived_at,archived_by,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_key) DO UPDATE SET ips=excluded.ips, mac=excluded.mac, last_seen=excluded.last_seen, updated_at=excluded.updated_at`,
		a.NodeKey, ips, a.MAC, a.Hostname, a.OS, a.Status, a.Owner, a.Department, a.Location, a.Description,
		a.FirstSeen, a.LastSeen, archivedAt, a.ArchivedBy, now, now)
	if err != nil {
		return 0, err
	}
	// 返回已存在/新建的 id
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM assets WHERE node_key=?`, a.NodeKey).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ArchiveAsset 归档：写入归属信息 + 归档时间。
func (s *Store) ArchiveAsset(nodeKey, owner, department, location, hostname, osName, description, by string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE assets SET status='archived', owner=?, department=?, location=?, hostname=?, os=?, description=?, archived_at=?, archived_by=?, updated_at=? WHERE node_key=?`,
		owner, department, location, hostname, osName, description, now, by, now, nodeKey)
	return err
}

// UpdateAsset 维护归档信息（不改 status）。
func (s *Store) UpdateAsset(nodeKey, owner, department, location, hostname, osName, description string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE assets SET owner=?, department=?, location=?, hostname=?, os=?, description=?, updated_at=? WHERE node_key=?`,
		owner, department, location, hostname, osName, description, now, nodeKey)
	return err
}

// AssetByKey 按 node_key 查资产，不存在返回 (nil, nil)。
func (s *Store) AssetByKey(key string) (*model.Asset, error) {
	a, err := scanAsset(s.db.QueryRow(assetColumns+` WHERE node_key=?`, key))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListAssets 查询资产（按状态过滤，空串=全部）。
func (s *Store) ListAssets(status string) ([]model.Asset, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.Query(assetColumns + ` ORDER BY status, last_seen DESC`)
	} else {
		rows, err = s.db.Query(assetColumns+` WHERE status=? ORDER BY last_seen DESC`, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DeleteAsset 删除资产（按 node_key）。
func (s *Store) DeleteAsset(nodeKey string) error {
	_, err := s.db.Exec(`DELETE FROM assets WHERE node_key=?`, nodeKey)
	return err
}

// DeleteAssetsByKeys 批量删除资产。
func (s *Store) DeleteAssetsByKeys(keys []string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	var total int64
	for _, k := range keys {
		if res, err := s.db.Exec(`DELETE FROM assets WHERE node_key=?`, k); err == nil {
			total += mustRowsAffected(res)
		}
	}
	return total, nil
}

// ---------- 端口记录（V1.2） ----------

const portColumns = `SELECT id,node_key,ip,port,proto,service,state,source,first_seen,last_seen FROM ports`

func scanPort(row rowScanner) (*model.PortRecord, error) {
	var p model.PortRecord
	err := row.Scan(&p.ID, &p.NodeKey, &p.IP, &p.Port, &p.Proto, &p.Service, &p.State, &p.Source, &p.FirstSeen, &p.LastSeen)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpsertPort 幂等写入端口记录（node_key+ip+port+proto 唯一）。
func (s *Store) UpsertPort(p *model.PortRecord) error {
	_, err := s.db.Exec(`INSERT INTO ports(node_key,ip,port,proto,service,state,source,first_seen,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_key,ip,port,proto) DO UPDATE SET service=excluded.service, state=excluded.state, source=excluded.source, last_seen=excluded.last_seen`,
		p.NodeKey, p.IP, p.Port, p.Proto, p.Service, p.State, p.Source, p.FirstSeen, p.LastSeen)
	return err
}

// UpsertPorts 批量幂等写入端口记录。
func (s *Store) UpsertPorts(ps []model.PortRecord) error {
	if len(ps) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO ports(node_key,ip,port,proto,service,state,source,first_seen,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_key,ip,port,proto) DO UPDATE SET service=excluded.service, state=excluded.state, source=excluded.source, last_seen=excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range ps {
		p := &ps[i]
		if _, err := stmt.Exec(p.NodeKey, p.IP, p.Port, p.Proto, p.Service, p.State, p.Source, p.FirstSeen, p.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListPorts 查询端口记录（可按 ip / node_key 过滤）。
func (s *Store) ListPorts(ip, nodeKey string) ([]model.PortRecord, error) {
	q := portColumns
	var args []any
	var conds []string
	if ip != "" {
		conds = append(conds, "ip=?")
		args = append(args, ip)
	}
	if nodeKey != "" {
		conds = append(conds, "node_key=?")
		args = append(args, nodeKey)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY ip, port"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.PortRecord
	for rows.Next() {
		p, err := scanPort(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// DeletePortsByKey 删除某主机的全部端口记录。
func (s *Store) DeletePortsByKey(nodeKey string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM ports WHERE node_key=?`, nodeKey)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func mustRowsAffected(res sql.Result) int64 {
	if res == nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}
