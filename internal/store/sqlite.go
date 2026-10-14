// Package store 提供 SQLite 持久化（modernc.org/sqlite 纯 Go 驱动，免 CGO）。
// 建表 schema：nodes, edges, sessions, events, whitelist, domains, audit, config。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
	return &Store{db: db}, nil
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

// CreateNode 创建节点，返回带 ID 的节点。
func (s *Store) CreateNode(n *model.Node) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO nodes(ips,mac,first_seen,last_seen,domain,labels,risk_level,active) VALUES(?,?,?,?,?,?,?,?)`,
		toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateNode 更新节点全部字段。
func (s *Store) UpdateNode(n *model.Node) error {
	_, err := s.db.Exec(
		`UPDATE nodes SET ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE id=?`,
		toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.ID)
	return err
}

// GetNode 按 ID 查询节点。
func (s *Store) GetNode(id int64) (*model.Node, error) {
	row := s.db.QueryRow(`SELECT id,ips,mac,first_seen,last_seen,domain,labels,risk_level,active FROM nodes WHERE id=?`, id)
	n, err := scanNode(row)
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
	err := row.Scan(&n.ID, &ips, &n.MAC, &n.FirstSeen, &n.LastSeen, &n.Domain, &labels, &n.RiskLevel, &active)
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
	rows, err := s.db.Query(`SELECT id,ips,mac,first_seen,last_seen,domain,labels,risk_level,active FROM nodes`)
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
