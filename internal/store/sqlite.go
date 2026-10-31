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
  active INTEGER NOT NULL DEFAULT 1,
  location TEXT NOT NULL DEFAULT ''
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
-- session_offsets：增量基准（V1.5.1）。
-- 与 sessions 表刻意分开：sessions 是「首次见到这条会话」的历史记录（只插一次），
-- 字节数停在首见那一刻；而重启后要用的是「关库前最后一次看到的累计值」。
-- 用历史表当增量基准，重启时基准偏小，仍在持续的会话会被整笔再算一次——
-- 这正是"重启几次 1.6GB 变 750GB"的来源。这里是运行态状态表，按五元组覆盖写。
CREATE TABLE IF NOT EXISTS session_offsets (
  five_tuple TEXT PRIMARY KEY,
  bytes INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME,
  last_seen DATETIME
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  node_id INTEGER NOT NULL DEFAULT 0,
  node_key TEXT NOT NULL DEFAULT '',
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
-- 变更页与趋势图都按 first_seen / last_seen 做时间范围筛选（V1.6）。
-- 没有索引时这两个查询是全表扫描 + 排序，而端口表本来就是最大的那张表
-- （一次 /16 全端口扫描就是几十万行），仪表盘会随之变慢。
CREATE INDEX IF NOT EXISTS idx_ports_first_seen ON ports(first_seen);
-- 复合索引不是"多此一举"：变更页的「消失」条件是
-- last_seen < ? AND first_seen < ?，只建 last_seen 单列索引时
-- SQLite 拿到范围后必须**回表**逐行取 first_seen 才能判定，实测 4.3 万行
-- 的 COUNT(*) 要 395ms；把 first_seen 也放进索引后变成纯索引遍历。
-- 左前缀仍是 last_seen，所以它同时顶替了单列索引，不需要再建一条。
CREATE INDEX IF NOT EXISTS idx_ports_last_first ON ports(last_seen, first_seen);
-- 端口状态刷新（MarkStalePorts：state='open' AND last_seen < ?）同样要覆盖索引，
-- 否则每轮维护都要回表扫一遍全表。
CREATE INDEX IF NOT EXISTS idx_ports_state_seen ON ports(state, last_seen);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
-- 趋势图按天统计新增资产，同样需要时间索引。
CREATE INDEX IF NOT EXISTS idx_assets_created ON assets(created_at);
-- 事件列表按状态/类型筛选并倒序分页；没有索引时每次都是全表扫描 + 排序。
-- 事件表是持续增长的（检测引擎每 2s 评估一轮），这条索引的价值随时间上升。
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, id DESC);
CREATE TABLE IF NOT EXISTS probes (
  probe_id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  last_seen DATETIME NOT NULL,
  created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL DEFAULT '',
  mac TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  batch TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_ip ON ledger(ip);
CREATE TABLE IF NOT EXISTS intel_iocs (
  indicator   TEXT PRIMARY KEY,
  kind        TEXT NOT NULL DEFAULT 'ip',
  verdict     TEXT NOT NULL DEFAULT 'unknown',
  score       INTEGER NOT NULL DEFAULT 0,
  tags        TEXT NOT NULL DEFAULT '[]',
  source      TEXT NOT NULL DEFAULT '',
  intel_ver   INTEGER NOT NULL DEFAULT 0,
  updated_at  DATETIME NOT NULL,
  received_at DATETIME NOT NULL,
  expires_at  DATETIME,
  raw         TEXT NOT NULL DEFAULT ''
);
-- 标红要按"命中即红旗"批量取，按 verdict + 数据时间倒序能只扫需要的行
CREATE INDEX IF NOT EXISTS idx_intel_verdict ON intel_iocs(verdict, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_received ON intel_iocs(received_at);
-- 主动发现任务账（V1.6）。只存"这次扫了什么、结果多少"，扫描结果本身在 ports 表：
-- 两处都存一份，迟早开始漂移。
CREATE TABLE IF NOT EXISTS discover_tasks (
  id            TEXT PRIMARY KEY,
  targets       TEXT NOT NULL DEFAULT '',
  profile       TEXT NOT NULL DEFAULT '',
  profile_label TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'running',
  total         INTEGER NOT NULL DEFAULT 0,
  done          INTEGER NOT NULL DEFAULT 0,
  alive         INTEGER NOT NULL DEFAULT 0,
  open_ports    INTEGER NOT NULL DEFAULT 0,
  fingerprints  INTEGER NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',
  created_by    TEXT NOT NULL DEFAULT '',
  started_at    DATETIME NOT NULL,
  finished_at   DATETIME
);
-- 任务页永远按"最新在前"翻，状态筛选是第二个入口，各配一条索引。
CREATE INDEX IF NOT EXISTS idx_disc_tasks_started ON discover_tasks(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_disc_tasks_status ON discover_tasks(status, started_at DESC);
`

// openDSN 给 SQLite 的 DSN 挂上连接级 pragma。
//
// 为什么要写进 DSN 而不是在 Open 里 Exec 一次：**pragma 是连接级的**，
// 连接池里每开一条新连接都要重新设一遍，Exec 只能覆盖当时那一条。
//
//   - busy_timeout  —— 写锁被别人占着时等一会儿，而不是立刻返回 database is locked；
//   - journal_mode  —— WAL：读不挡写、写不挡读（库级属性，写上只是保证新库也一致）；
//   - synchronous=NORMAL —— WAL 下的推荐值。FULL 会在每次提交 fsync 一次，
//     探针上报是每请求一个事务，于是"每 400 条报文一次磁盘同步"，
//     真实网络下吞吐被 fsync 卡死。NORMAL 在 WAL 里已经能扛进程崩溃，
//     只有操作系统掉电才可能丢最后几个事务，对流量日志是可接受的取舍；
//   - _txlock=immediate —— 事务一开始就拿写锁。默认的 DEFERRED 事务若先读后写，
//     锁升级失败时 SQLite 会**立刻**返回 SQLITE_BUSY（不理会 busy_timeout，
//     否则就成了死锁），表现为偶发写失败。
func openDSN(path string) string {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return path // 内存库不开连接池，见 Open
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep +
		"_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_txlock=immediate"
}

// Open 打开（不存在则创建）SQLite 数据库并建表。
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", openDSN(path))
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 连接数策略（V1.6.0 重做）。
	//
	// 旧实现是 SetMaxOpenConns(1)：理由是"SQLite 单写者，多连接会 database is locked"。
	// 单写者是对的，但**读不需要写锁**——WAL 下读走快照，根本不该排进写队列。
	// 把连接限制成 1 条，等于让全进程的读都排在写事务后面：
	// 实测 68k 会话、探针持续上报时，一条"查白名单"的 SQL 要等 2.4 秒才拿到连接，
	// 而它本身只返回 0 行；评估器每轮因此固定多花 2~3 秒，
	// 而这段时间又被算进"评估慢"，把问题指错了方向。
	//
	// 现在：写仍然互斥（靠 SQLite 的写锁 + busy_timeout 排队），读并发。
	// 内存库(:memory:)必须保持 1 条连接——每条连接都是一个独立的内存数据库。
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(32)
		db.SetMaxIdleConns(32)
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
	// 1.2：端口记录扩容服务指纹列（在线加列，老库直接升级，无需手工迁移）
	if err := migratePortFingerprint(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("端口指纹迁移失败: %w", err)
	}
	// 1.5.2：会话历史表补唯一键（先清理历史重复行，再建索引）
	if err := migrateSessionUnique(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("会话表唯一键迁移失败: %w", err)
	}
	// 1.3：事件补 node_key。只加列不重建：事件是历史记录，
	// 重建会丢掉"创建时间"这一列最核心的信息（它决定了保留期与时间线）。
	if err := ensureColumn(db, "events", "node_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		db.Close()
		return nil, fmt.Errorf("事件 node_key 迁移失败: %w", err)
	}
	// 回填：老事件只有自增 node_id，节点还在的话能直接反查出稳定 key，
	// 救回"升级后历史事件的关联节点变成裸数字"的观感问题。节点已删的行留空，
	// 读取时会显示为"（已不在拓扑）"。
	if _, err := db.Exec(`UPDATE events SET node_key = (
	        SELECT nodes.node_key FROM nodes WHERE nodes.id = events.node_id)
	    WHERE node_key = '' AND EXISTS (
	        SELECT 1 FROM nodes WHERE nodes.id = events.node_id)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("事件 node_key 回填失败: %w", err)
	}
	return &Store{db: db}, nil
}

// migrateSessionUnique 给 sessions 表补五元组唯一键（V1.5.2）。
//
// 为什么必须唯一：这张表是"会话历史"，写到它里面的动作是 INSERT。旧实现在进程内
// 用 emitted 标记保证"同一个五元组只插一次"，但那个标记只活在本次进程里——
// 重启之后，所有仍在持续的会话又都成了"首次见到"，于是再插一行。
// 现场实测：灌同一个 pcap、中间重启一次，两条五元组各出现两行。
// 这类重复行没有任何独立信息（字节数停在首见那一刻），留着只会让表持续膨胀。
//
// 迁移顺序不能反：必须先删重复行，再建唯一索引。历史库（比如跑了 70 小时、
// 攒了 60 万行的那个）里一定已经有重复，直接建索引会失败、服务起不来。
func migrateSessionUnique(db *sql.DB) error {
	if indexExists(db, "idx_sessions_ft") {
		return nil
	}
	// 去重：同一五元组只保留 id 最小（最早）的一行。
	// 保留最早的行而不是最新，是因为这一行的 first_seen 才是真正的"首次见到"。
	if _, err := db.Exec(`DELETE FROM sessions WHERE id NOT IN (
	        SELECT MIN(id) FROM sessions GROUP BY five_tuple)`); err != nil {
		return fmt.Errorf("清理会话重复行失败: %w", err)
	}
	// 保留期清理按 last_seen 过滤，没有索引就是全表扫
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen)`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_ft ON sessions(five_tuple)`)
	return err
}

// indexExists 判断索引是否已存在（迁移的幂等判据）。
func indexExists(db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// migratePortFingerprint 给 ports 表补指纹列。

// 用 ADD COLUMN 而不是重建表：端口表是历史累积的观测数据，重建一次等于把所有
// "首次发现时间"重置为迁移当天，账实对照会全部失真。
func migratePortFingerprint(db *sql.DB) error {
	cols := []struct{ name, decl string }{
		{"product", "TEXT NOT NULL DEFAULT ''"},
		{"version", "TEXT NOT NULL DEFAULT ''"},
		{"title", "TEXT NOT NULL DEFAULT ''"},
		{"banner", "TEXT NOT NULL DEFAULT ''"},
		{"tls_cn", "TEXT NOT NULL DEFAULT ''"},
		{"tls_names", "TEXT NOT NULL DEFAULT '[]'"},
		{"favicon", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range cols {
		if err := ensureColumn(db, "ports", c.name, c.decl); err != nil {
			return err
		}
	}
	return nil
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
	if err := ensureColumn(db, "nodes", "location", "TEXT NOT NULL DEFAULT ''"); err != nil {
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
		`INSERT INTO nodes(node_key,location,ips,mac,first_seen,last_seen,domain,labels,risk_level,active) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		n.NodeKey, n.Location, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active))
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
		`UPDATE nodes SET node_key=?,location=?,ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE id=?`,
		n.NodeKey, n.Location, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.ID)
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
			`UPDATE nodes SET node_key=?,location=?,ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE id=?`,
			n.NodeKey, n.Location, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
		if aff, err := res.RowsAffected(); err == nil && aff > 0 {
			continue
		}
		_, err = tx.Exec(
			`INSERT INTO nodes(id,node_key,location,ips,mac,first_seen,last_seen,domain,labels,risk_level,active) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			n.ID, n.NodeKey, n.Location, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active))
		if err != nil {
			// id 被同名 key 的旧行占用（理论上不会：恢复时已加载全部行）
			// 退化为按 node_key 更新那一行，保持库内不重复。
			if _, err2 := tx.Exec(
				`UPDATE nodes SET location=?,ips=?,mac=?,first_seen=?,last_seen=?,domain=?,labels=?,risk_level=?,active=? WHERE node_key=?`,
				n.Location, toJSON(n.IPs), n.MAC, n.FirstSeen, n.LastSeen, n.Domain, toJSON(n.Labels), n.RiskLevel, b2i(n.Active), n.NodeKey); err2 != nil {
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

// nodeColumns 节点查询列清单（含 P0-2 稳定 key 列 + V1.3 探针位置列）。
const nodeColumns = `SELECT id,node_key,location,ips,mac,first_seen,last_seen,domain,labels,risk_level,active FROM nodes`

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
	err := row.Scan(&n.ID, &n.NodeKey, &n.Location, &ips, &n.MAC, &n.FirstSeen, &n.LastSeen, &n.Domain, &labels, &n.RiskLevel, &active)
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
// SaveSession 写入/更新一条会话历史（V1.5.2 起按五元组幂等）。
//
// 语义变化说明：旧实现是纯 INSERT，靠"进程内首次"去重，重启后同一会话会再插一行；
// 现在走 ON CONFLICT，同一个五元组永远只有一行，重启后落到 UPDATE 分支。
// 附带的好处是这一行会跟着会话演进（字节数、SNI、JA3 都是最新观测值），
// 而不是永远停在"首次见到那一刻"——后者对排查毫无用处。
//
// 字段用 CASE 保护：新值为空时不覆盖已有值。一条 keep-alive 连接后续的报文里
// 往往没有 ClientHello / HTTP 头，直接覆盖会把先前解析到的 SNI、Host 洗掉。
// sessionUpsertSQL 会话历史写入语句的唯一来源（单条与批量共用，避免两处漂移）。
//
// ON CONFLICT 是「幂等 upsert + 空值不覆盖」：早期版本是裸 INSERT，同一个五元组
// 出现两次就报错；而空值覆盖更是会洗掉已经采到的证据（探针先报了 SNI，
// 下一批 flows 没带，库里的 SNI 就没了）。
const sessionUpsertSQL = `INSERT INTO sessions(five_tuple,mac,start_ttl,first_seen,last_seen,bytes_up,bytes_down,packets,sni,http_host,ja3,ja4,is_long_conn,heartbeat_interval_ms,closed)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT(five_tuple) DO UPDATE SET
	   last_seen=excluded.last_seen,
	   bytes_up=excluded.bytes_up,
	   bytes_down=excluded.bytes_down,
	   packets=excluded.packets,
	   mac=CASE WHEN excluded.mac<>'' THEN excluded.mac ELSE sessions.mac END,
	   start_ttl=CASE WHEN excluded.start_ttl>0 THEN excluded.start_ttl ELSE sessions.start_ttl END,
	   sni=CASE WHEN excluded.sni<>'' THEN excluded.sni ELSE sessions.sni END,
	   http_host=CASE WHEN excluded.http_host<>'' THEN excluded.http_host ELSE sessions.http_host END,
	   ja3=CASE WHEN excluded.ja3<>'' THEN excluded.ja3 ELSE sessions.ja3 END,
	   ja4=CASE WHEN excluded.ja4<>'' THEN excluded.ja4 ELSE sessions.ja4 END,
	   is_long_conn=MAX(sessions.is_long_conn, excluded.is_long_conn),
	   heartbeat_interval_ms=CASE WHEN excluded.heartbeat_interval_ms>0 THEN excluded.heartbeat_interval_ms ELSE sessions.heartbeat_interval_ms END,
	   closed=MAX(sessions.closed, excluded.closed)`

func (s *Store) SaveSession(ses *model.Session) (int64, error) {
	res, err := s.db.Exec(sessionUpsertSQL,
		toJSON(ses.FiveTuple), ses.MAC, ses.StartTTL, ses.FirstSeen, ses.LastSeen,
		ses.BytesUp, ses.BytesDown, ses.Packets, ses.SNI, ses.HTTPHost, ses.JA3, ses.JA4,
		b2i(ses.IsLongConn), ses.HeartbeatIntervalMs, b2i(ses.Closed))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SaveSessions 批量写入会话历史（一次事务、一条预编译语句）。
//
// 单条 SaveSession 每次都是一次隐式事务，每行都要一次提交/落盘。探针一批上报
// 里可能有几百条新会话，逐条写会把上报接口的耗时按行数线性拉长（实测约 1ms/条）。
// 批量写把 N 次提交压成 1 次。
func (s *Store) SaveSessions(list []model.Session) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(sessionUpsertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range list {
		ses := &list[i]
		if _, err := stmt.Exec(
			toJSON(ses.FiveTuple), ses.MAC, ses.StartTTL, ses.FirstSeen, ses.LastSeen,
			ses.BytesUp, ses.BytesDown, ses.Packets, ses.SNI, ses.HTTPHost, ses.JA3, ses.JA4,
			b2i(ses.IsLongConn), ses.HeartbeatIntervalMs, b2i(ses.Closed)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteSessionsBefore 删除 last_seen 早于 cutoff 的会话历史，返回删除行数。
//
// 这是 sessions 表唯一的回收路径（V1.5.2 新增）。没有它，这张表就是纯粹的
// "历史唯一连接数"累加器：现场实测 3 天 60 万行 / 148MB，一年约 18GB，
// 而界面上看不到任何迹象。
func (s *Store) DeleteSessionsBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
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

// SessionOffset 一条会话的累计计数与最后活跃时间。
//
// 存在的理由是"重启不能把流量算两遍"：引擎对边的字节是按**增量**累加的
// （探针每几秒上报一次累计值），而增量依赖"上次看到多少"。进程重启后这个
// "上次"如果丢了，同一条仍在持续的会话就会被当成新会话整笔再加一次——
// 重启几次，图上的 1.6GB 就变成 750GB。数字大了没人发现，因为界面上只是一个更大的数。
type SessionOffset struct {
	Bytes     int64
	Packets   int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// SessionOffsets 返回最近 since 之后活跃过的会话的累计计数，键为 FiveTuple.Key()。
//
// 读的是 session_offsets（运行态状态表），不是 sessions（历史表）。
// 历史表只在会话首次出现时插一行，字节数停在首见那一刻；拿它当增量基准，
// 重启后基准偏小，仍在持续的会话会被整笔再算一次。
//
// 时间过滤刻意放在 Go 侧：这些 DATETIME 列里存的是 RFC3339 文本（带 7 位小数秒），
// 而驱动把 time.Time 参数绑成 Go 自己的 "2006-01-02 15:04:05 -0700 MST" 格式，
// 两者字符串比较毫无意义（实测 `last_seen >= ?` 一条都匹配不到）；
// julianday() 对这种 7 位小数秒的存储值直接返回 NULL。
func (s *Store) SessionOffsets(since time.Time) (map[string]SessionOffset, error) {
	rows, err := s.db.Query(
		`SELECT five_tuple, bytes, packets, first_seen, last_seen FROM session_offsets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]SessionOffset, 1024)
	for rows.Next() {
		var ft string
		var total, packets int64
		var first, last time.Time
		if err := rows.Scan(&ft, &total, &packets, &first, &last); err != nil {
			return nil, err
		}
		if !last.IsZero() && last.Before(since) {
			continue
		}
		out[ft] = SessionOffset{Bytes: total, Packets: packets, FirstSeen: first, LastSeen: last}
	}
	return out, rows.Err()
}

// SaveSessionOffsets 覆盖写入增量基准（按五元组 upsert）。
//
// 键直接用 FiveTuple.Key()：写入方手里就是这个键，读回来也用同一个键，
// 中间不再经过 JSON 反序列化，少一层"存进去和取出来不是同一个东西"的机会。
func (s *Store) SaveSessionOffsets(rows map[string]SessionOffset) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(
		`INSERT INTO session_offsets(five_tuple,bytes,packets,first_seen,last_seen) VALUES(?,?,?,?,?)
		 ON CONFLICT(five_tuple) DO UPDATE SET bytes=excluded.bytes, packets=excluded.packets,
		 first_seen=excluded.first_seen, last_seen=excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, o := range rows {
		if _, err := stmt.Exec(k, o.Bytes, o.Packets, o.FirstSeen, o.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneSessionOffsets 清掉过期基准：会话早就结束了，留着只会让表一直长。
func (s *Store) PruneSessionOffsets(before time.Time) error {
	rows, err := s.db.Query(`SELECT five_tuple, last_seen FROM session_offsets`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var k string
		var last time.Time
		if err := rows.Scan(&k, &last); err != nil {
			rows.Close()
			return err
		}
		// 时间比较同样放在 Go 侧，理由见 SessionOffsets。
		if !last.IsZero() && last.Before(before) {
			stale = append(stale, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range stale {
		if _, err := s.db.Exec(`DELETE FROM session_offsets WHERE five_tuple=?`, k); err != nil {
			return err
		}
	}
	return nil
}

// ---------- RiskEvent CRUD ----------

// CreateEvent 创建风险事件。
// eventInsertSQL 事件写入语句的唯一来源（单条与批量共用）。
const eventInsertSQL = `INSERT INTO events(type,node_id,node_key,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`

// prepareEventForInsert 补齐缺省字段（单条与批量必须走同一套默认值，
// 否则同一个事件走两条路会得到不同的 created_at / status）。
func prepareEventForInsert(e *model.RiskEvent) {
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.Status == "" {
		e.Status = model.EventStatusPending
	}
}

func (s *Store) CreateEvent(e *model.RiskEvent) (int64, error) {
	prepareEventForInsert(e)
	res, err := s.db.Exec(eventInsertSQL,
		e.Type, e.NodeID, e.NodeKey, e.Title, e.Detail, toJSON(e.Evidence), e.Status, e.Level,
		e.CreatedAt, e.UpdatedAt, e.ReviewNote, e.Reviewer)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreateEvents 批量新建事件（一次事务），返回与入参顺序一致的 id。
//
// 评估器一轮可能新建上百条事件（网络里每出现一台新主机就是一条）。
// 单条 INSERT 是自动提交，每条都要一次提交与落盘；在 SQLite 这个"单写者"上，
// 一分钟几百次提交会把写锁占满，表现成"上报接口偶发卡十几秒"——
// 真相是写入方在排队，而不是上报本身慢。
func (s *Store) CreateEvents(list []*model.RiskEvent) ([]int64, error) {
	if len(list) == 0 {
		return nil, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(eventInsertSQL)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	ids := make([]int64, len(list))
	for i, e := range list {
		prepareEventForInsert(e)
		res, err := stmt.Exec(
			e.Type, e.NodeID, e.NodeKey, e.Title, e.Detail, toJSON(e.Evidence), e.Status, e.Level,
			e.CreatedAt, e.UpdatedAt, e.ReviewNote, e.Reviewer)
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
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

// UpdateEventEvidenceBatch 批量更新事件证据（一次事务）。
//
// 评估器每轮可能刷新成百上千条事件证据，逐条 UPDATE 等于每条一次提交；
// 稳态下这批写会被评估周期反复放大，把整个库的写路径占满。
func (s *Store) UpdateEventEvidenceBatch(ids []int64, evidences []map[string]string) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) != len(evidences) {
		return fmt.Errorf("批量更新证据参数不匹配: ids=%d evidences=%d", len(ids), len(evidences))
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`UPDATE events SET evidence=?, updated_at=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now()
	for i := range ids {
		if _, err := stmt.Exec(toJSON(evidences[i]), now, ids[i]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanEvent(row rowScanner) (*model.RiskEvent, error) {
	var e model.RiskEvent
	var evidence string
	err := row.Scan(&e.ID, &e.Type, &e.NodeID, &e.NodeKey, &e.Title, &e.Detail, &evidence, &e.Status, &e.Level,
		&e.CreatedAt, &e.UpdatedAt, &e.ReviewNote, &e.Reviewer)
	if err != nil {
		return nil, err
	}
	fromJSON(evidence, &e.Evidence)
	return &e, nil
}

// GetEvent 按 ID 查询事件。
func (s *Store) GetEvent(id int64) (*model.RiskEvent, error) {
	e, err := scanEvent(s.db.QueryRow(`SELECT id,type,node_id,node_key,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer FROM events WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// ListEventsForDedup 返回去重索引需要的事件行：窗口内的 pending/confirmed，
// 只取 5 个必要列。
//
// 为什么单独开一个方法而不是复用 ListEvents：
//
//   - 去重只关心 (type, node_id) 与 evidence，标题/详情/node_key/复核意见全是白读的；
//   - 24h 窗口必须由 SQL 过滤。事件表没有保留期，长期在线部署会一直长，
//     而"每轮评估读全表"意味着评估耗时随运行时长线性劣化——开发机跑几小时
//     看不出，现场跑一周就是"服务越用越卡"。
//
// 时间比较依赖"同一偏移下字符串序 == 时间序"（modernc 把 time.Time 绑成
// RFC3339，见 timefmt_test.go 的锁定用例）。
func (s *Store) ListEventsForDedup(since time.Time) ([]model.RiskEvent, error) {
	rows, err := s.db.Query(
		`SELECT id,type,node_id,evidence,created_at,updated_at FROM events
		  WHERE status IN (?,?) AND created_at >= ? ORDER BY id`,
		model.EventStatusPending, model.EventStatusConfirmed, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.RiskEvent, 0, 256)
	for rows.Next() {
		var e model.RiskEvent
		var evidence string
		if err := rows.Scan(&e.ID, &e.Type, &e.NodeID, &evidence, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		fromJSON(evidence, &e.Evidence)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEvents 按状态/类型筛选查询事件（空串表示不筛选）。

// 无限量：内部统计与测试用。对外接口一律走 ListEventsPaged，避免一次拉全表。
func (s *Store) ListEvents(status, evType string) ([]model.RiskEvent, error) {
	return s.ListEventsPaged(EventFilter{Status: status, Type: evType}, 0, 0)
}

// EventFilter 事件列表的筛选条件。
//
// 用结构体而不是位置参数：条件是会长的（1.3.1 加了 Keyword，以后可能加 level / 时间范围），
// 位置参数每加一个就要改所有调用点，而且调用处 `ListEventsPaged("", "", ...)` 完全看不出
// 那两个空串各自是什么。更重要的是——列表与计数必须共用同一份条件对象，
// 两边各拼一遍 WHERE 就是"共 N 条"和列表对不上的根源。
type EventFilter struct {
	Status  string
	Type    string
	Keyword string // 标题/详情模糊匹配
}

// eventWhere 事件筛选条件的唯一构造点（列表与计数必须完全一致，
// 否则"共 N 条"和实际列表对不上，用户会以为丢数据）。
func eventWhere(f EventFilter) (string, []any) {
	where := " WHERE 1=1"
	var args []any
	if f.Status != "" {
		where += " AND status=?"
		args = append(args, f.Status)
	}
	if f.Type != "" {
		where += " AND type=?"
		args = append(args, f.Type)
	}
	if cond, kwArgs := likeAny([]string{"title", "detail"}, f.Keyword); cond != "" {
		where += " AND " + cond
		args = append(args, kwArgs...)
	}
	return where, args
}

// ListEventsPaged 分页查询事件（limit<=0 且 offset<=0 表示不限量）。
func (s *Store) ListEventsPaged(f EventFilter, limit, offset int) ([]model.RiskEvent, error) {
	where, args := eventWhere(f)
	query, args := applyPage(`SELECT id,type,node_id,node_key,title,detail,evidence,status,level,created_at,updated_at,review_note,reviewer FROM events`+where+` ORDER BY id DESC`, args, limit, offset)
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

// CountEvents 事件总数（与 ListEventsPaged 同一套筛选条件）。
func (s *Store) CountEvents(f EventFilter) (int, error) {
	where, args := eventWhere(f)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events`+where, args...).Scan(&n)
	return n, err
}

// ---------- 模糊匹配工具 ----------

// escapeLike 转义 LIKE 的通配符。
//
// 不转义的后果不是安全问题（参数仍是绑定的），而是**语义错**：
// 用户在搜索框里输入 "100%" 或 "10_0_0_1"，这两个字符会被当通配符，
// 于是"搜什么都能匹配到"，看起来像搜索失灵。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// likeAny 对多列做「任一命中」的模糊匹配，返回 (条件, 参数)。
// 空关键字返回空条件，调用方据此跳过拼接。
func likeAny(cols []string, keyword string) (string, []any) {
	kw := strings.TrimSpace(keyword)
	if kw == "" || len(cols) == 0 {
		return "", nil
	}
	pat := "%" + escapeLike(kw) + "%"
	parts := make([]string, 0, len(cols))
	args := make([]any, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, c+` LIKE ? ESCAPE '\'`)
		args = append(args, pat)
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
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

// SyncAssetsFromNodes 把拓扑节点批量同步进资产库（V1.5.2）。
//
// 替代 API 层原来的"逐节点 SELECT + 逐条 UPSERT"：那是 O(N) 次往返，
// 2000 台主机就是 4000 条独立语句，资产页一次加载（/assets + /assets/stats）
// 还要把它跑两遍，只能靠 2 秒节流掩盖问题。
//
// 语义与原实现严格一致：
//   - 新节点 → status=unarchived（账外资产，等待人工归档）
//   - 已存在 → 只刷新 ips / mac / last_seen；已归档资产的归属信息
//     （owner / department / 物理位置 / 描述）一律保留，不能被自动同步覆盖成空值
//   - 位置只有"未归档"才跟随探针，已归档以人工填写为准
func (s *Store) SyncAssetsFromNodes(nodes []model.Node, now time.Time) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`INSERT INTO assets(node_key,ips,mac,hostname,os,status,owner,department,location,description,
		                    first_seen,last_seen,created_at,updated_at)
		 VALUES(?,?,?,'','','unarchived','','',?,'',?,?,?,?)
		 ON CONFLICT(node_key) DO UPDATE SET
		   ips=excluded.ips,
		   mac=excluded.mac,
		   last_seen=excluded.last_seen,
		   updated_at=excluded.updated_at,
		   location=CASE WHEN assets.status='unarchived' AND excluded.location<>''
		                 THEN excluded.location ELSE assets.location END
		 -- WHERE 守卫（V1.6）：这条 upsert 每次会带上全部主机（6 万台就是 6 万行），
		 -- 而绝大多数行的内容根本没变——只是被一遍遍重写成同样的值。
		 -- 实测一次全量同步占着写锁 2.8 秒，每 5 秒跑一次，等于写锁一半时间被这一件事占着，
		 -- 探针上报就排队到 3 秒。加上条件后无变化的行不产生页写。
		 WHERE excluded.last_seen > assets.last_seen
		    OR excluded.ips <> assets.ips
		    OR excluded.mac <> assets.mac`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for i := range nodes {
		nd := &nodes[i]
		if nd.NodeKey == "" {
			continue
		}
		first := nd.FirstSeen
		if first.IsZero() {
			first = now
		}
		last := nd.LastSeen
		if last.IsZero() {
			last = now
		}
		if _, err := stmt.Exec(nd.NodeKey, toJSON(nd.IPs), nd.MAC, nd.Location,
			first, last, now, now); err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit()
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
// ArchiveAsset 归档登记（未归档 → 已归档，写归属信息）。
//
// 0 行受影响要报错，不能静默成功：资产行是由 syncAssets 从拓扑懒同步出来的，
// 如果调用方在资产行还不存在时就归档，UPDATE 会匹配 0 行而返回 nil——
// 接口回 {"ok":true}，界面刷新后归属还是空的。这类"成功但没生效"最难查：
// 日志里只有一条正常的 archive 审计，没有任何异常。
func (s *Store) ArchiveAsset(nodeKey, owner, department, location, hostname, osName, description, by string) error {
	now := time.Now()
	res, err := s.db.Exec(`UPDATE assets SET status='archived', owner=?, department=?, location=?, hostname=?, os=?, description=?, archived_at=?, archived_by=?, updated_at=? WHERE node_key=?`,
		owner, department, location, hostname, osName, description, now, by, now, nodeKey)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("资产记录不存在（node_key=%s），请先刷新资产列表让节点同步入库", nodeKey)
	}
	return nil
}

// UpdateAsset 维护归档信息（不改 status）。语义与 ArchiveAsset 一致：
// 0 行受影响视为失败，理由同上。
func (s *Store) UpdateAsset(nodeKey, owner, department, location, hostname, osName, description string) error {
	now := time.Now()
	res, err := s.db.Exec(`UPDATE assets SET owner=?, department=?, location=?, hostname=?, os=?, description=?, updated_at=? WHERE node_key=?`,
		owner, department, location, hostname, osName, description, now, nodeKey)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("资产记录不存在（node_key=%s）", nodeKey)
	}
	return nil
}

// AssetByKey 按 node_key 查资产，不存在返回 (nil, nil)。
func (s *Store) AssetByKey(key string) (*model.Asset, error) {
	a, err := scanAsset(s.db.QueryRow(assetColumns+` WHERE node_key=?`, key))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// AssetFilter 资产列表的筛选条件（列表与计数同源）。
type AssetFilter struct {
	Status  string
	Keyword string // IP/MAC/主机名/系统/归属单位/归属人 模糊匹配
}

// assetWhere 资产筛选条件的唯一构造点。
func assetWhere(f AssetFilter) (string, []any) {
	var conds []string
	var args []any
	if f.Status != "" {
		conds = append(conds, "status=?")
		args = append(args, f.Status)
	}
	// ips 是 JSON 数组文本（如 ["10.0.0.1","10.0.0.2"]），LIKE 能匹配到里面的 IP。
	if cond, kwArgs := likeAny(
		[]string{"ips", "mac", "hostname", "os", "owner", "department"}, f.Keyword); cond != "" {
		conds = append(conds, cond)
		args = append(args, kwArgs...)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListAssets 查询资产（按状态过滤，空串=全部）。无限量，内部/测试用。
func (s *Store) ListAssets(status string) ([]model.Asset, error) {
	return s.ListAssetsPaged(AssetFilter{Status: status}, 0, 0)
}

// ListAssetsPaged 分页查询资产（limit<=0 且 offset<=0 表示不限量）。
func (s *Store) ListAssetsPaged(f AssetFilter, limit, offset int) ([]model.Asset, error) {
	where, args := assetWhere(f)
	order := ` ORDER BY status, last_seen DESC, node_key`
	if f.Status != "" {
		order = ` ORDER BY last_seen DESC, node_key`
	}
	query, args := applyPage(assetColumns+where+order, args, limit, offset)
	rows, err := s.db.Query(query, args...)
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

// CountAssets 资产总数（与 ListAssetsPaged 同一套筛选条件）。
func (s *Store) CountAssets(f AssetFilter) (int, error) {
	where, args := assetWhere(f)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM assets`+where, args...).Scan(&n)
	return n, err
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

const portColumns = `SELECT id,node_key,ip,port,proto,service,state,source,first_seen,last_seen,
	product,version,title,banner,tls_cn,tls_names,favicon FROM ports`

func scanPort(row rowScanner) (*model.PortRecord, error) {
	var p model.PortRecord
	var tlsNames string
	err := row.Scan(&p.ID, &p.NodeKey, &p.IP, &p.Port, &p.Proto, &p.Service, &p.State, &p.Source,
		&p.FirstSeen, &p.LastSeen, &p.Product, &p.Version, &p.Title, &p.Banner, &p.TLSCN, &tlsNames, &p.Favicon)
	if err != nil {
		return nil, err
	}
	if tlsNames != "" && tlsNames != "[]" {
		fromJSON(tlsNames, &p.TLSNames)
	}
	return &p, nil
}

// 指纹列只能"有则覆盖"，不能被空值抹掉：
// 同一个端口会同时被流量提取（无指纹）和主动发现（有指纹）写两次，
// 若直接 excluded.product 覆盖，一次流量写入就会把辛苦扫到的产品名清空。
const portUpsertConflict = `ON CONFLICT(node_key,ip,port,proto) DO UPDATE SET
	service=CASE WHEN excluded.service<>'' THEN excluded.service ELSE ports.service END,
	state=excluded.state, source=excluded.source, last_seen=excluded.last_seen,
	product=CASE WHEN excluded.product<>'' THEN excluded.product ELSE ports.product END,
	version=CASE WHEN excluded.version<>'' THEN excluded.version ELSE ports.version END,
	title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE ports.title END,
	banner=CASE WHEN excluded.banner<>'' THEN excluded.banner ELSE ports.banner END,
	tls_cn=CASE WHEN excluded.tls_cn<>'' THEN excluded.tls_cn ELSE ports.tls_cn END,
	tls_names=CASE WHEN excluded.tls_names NOT IN ('','[]') THEN excluded.tls_names ELSE ports.tls_names END,
	favicon=CASE WHEN excluded.favicon<>'' THEN excluded.favicon ELSE ports.favicon END`

const portUpsertSQL = `INSERT INTO ports(node_key,ip,port,proto,service,state,source,first_seen,last_seen,
	product,version,title,banner,tls_cn,tls_names,favicon)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ` + portUpsertConflict

// PortStaleAfter 端口多久没再被观测到就标记为 stale（V1.5.2）。
//
// 为什么需要它：ports 表原先只有写入，唯一的删除路径是"资产被清理时连带删"。
// 结果是端口列表会永久腐烂——一台机器三年前开过 3389，列表里就一直是 3389，
// 而且和"今天确实在开"长得一模一样。对"理清网内结构"这个定位来说，
// 一条陈旧的开放端口比没有这条记录更糟：它会误导处置优先级。
//
// 30 天是折中：内网设备很少有超过一个月完全不上线的正常情况；
// 真离线那么久的机器，本来就该走离线清理，端口跟着变 stale 正好一致。
const PortStaleAfter = 30 * 24 * time.Hour

// stalePortChunk 单次提交标记的行数。
//
// 一次 UPDATE 打完 5 万行会把这期间的所有写入挡在门外：Windows runner 上实测
// 24k 行要 5.9 秒，等于维护循环每跑一轮，探针上报就卡 5.9 秒。分块后每批只持锁
// 几十毫秒，批间让出写锁，上报最多被推迟一小段。
//
// 每批仍然是**集合更新**（不是逐行 prepared statement）：逐行版实测 1.29s，
// 比整批还慢——一次集合更新的代价远小于两万次语句执行。分块只为缩短持锁时间，
// 不能顺手把算法退化成逐行。
//
// 声明成 var 而不是 const，是为了让用例能把它调小去验证"循环边界与末批余数"，
// 生产代码不应修改它。
var stalePortChunk = 5000

// MarkStalePorts 把超过 staleAfter 未再观测到的端口标记为 stale，返回受影响行数。
//
// 只改 state，不删行：曾经开放过这件事本身是证据（尤其是事后回溯），
// 但必须让它和"当前开放"在界面上区分开。
//
// 分块提交（V1.6.1）：每批独立事务，批间释放写锁。子查询先物化再更新，
// 所以 LIMIT 的语义不会随语句内部执行顺序漂移；被改掉的行下一轮不再满足
// state='open'，扫描范围自然收窄，直到没有候选为止。
func (s *Store) MarkStalePorts(before time.Time) (int64, error) {
	const sqlStmt = `UPDATE ports SET state='stale'
	                 WHERE id IN (SELECT id FROM ports
	                              WHERE state='open' AND last_seen < ? LIMIT ?)`
	var total int64
	for {
		res, err := s.db.Exec(sqlStmt, before, stalePortChunk)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n == 0 {
			return total, nil
		}
	}
}

// UpsertPort 写入/更新单条端口记录。
// UpsertPort 幂等写入端口记录（node_key+ip+port+proto 唯一）。
func (s *Store) UpsertPort(p *model.PortRecord) error {
	_, err := s.db.Exec(portUpsertSQL,
		p.NodeKey, p.IP, p.Port, p.Proto, p.Service, p.State, p.Source, p.FirstSeen, p.LastSeen,
		p.Product, p.Version, p.Title, p.Banner, p.TLSCN, toJSON(tlsNamesOrEmpty(p.TLSNames)), p.Favicon)
	return err
}

func tlsNamesOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
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
	stmt, err := tx.Prepare(portUpsertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range ps {
		p := &ps[i]
		if _, err := stmt.Exec(p.NodeKey, p.IP, p.Port, p.Proto, p.Service, p.State, p.Source, p.FirstSeen, p.LastSeen,
			p.Product, p.Version, p.Title, p.Banner, p.TLSCN, toJSON(tlsNamesOrEmpty(p.TLSNames)), p.Favicon); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PortFilter 端口记录的筛选条件（列表与计数同源）。
type PortFilter struct {
	IP      string // 精确匹配
	NodeKey string // 精确匹配
	Keyword string // IP/服务/产品/标题/Banner 模糊匹配
}

// ListPorts 查询端口记录（可按 ip / node_key 过滤）。
func (s *Store) ListPorts(ip, nodeKey string) ([]model.PortRecord, error) {
	return s.ListPortsPaged(PortFilter{IP: ip, NodeKey: nodeKey}, 0, 0)
}

// portWhere 端口记录筛选条件的唯一构造点（列表与计数共用）。
func portWhere(f PortFilter) (string, []any) {
	var conds []string
	var args []any
	if f.IP != "" {
		conds = append(conds, "ip=?")
		args = append(args, f.IP)
	}
	if f.NodeKey != "" {
		conds = append(conds, "node_key=?")
		args = append(args, f.NodeKey)
	}
	if cond, kwArgs := likeAny(
		[]string{"ip", "service", "product", "version", "title", "banner", "tls_cn"}, f.Keyword); cond != "" {
		conds = append(conds, cond)
		args = append(args, kwArgs...)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListPortsPaged 分页查询端口记录（limit<=0 且 offset<=0 表示不限量）。
func (s *Store) ListPortsPaged(f PortFilter, limit, offset int) ([]model.PortRecord, error) {
	where, args := portWhere(f)
	// 排序键带上 id 兜底：同一 IP:port 可能因 node_key 不同存在多行，
	// 只按 (ip,port) 排序时 LIMIT 分页会出现"某行在两页都出现/都不出现"。
	q, args := applyPage(portColumns+where+` ORDER BY ip, port, id`, args, limit, offset)
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

// CountPorts 端口记录总数（与 ListPortsPaged 同一套筛选条件）。
func (s *Store) CountPorts(f PortFilter) (int, error) {
	where, args := portWhere(f)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM ports`+where, args...).Scan(&n)
	return n, err
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

// ---------- 探针注册（V1.3：按探针位置归纳拓扑） ----------

// UpsertProbe 幂等写入/更新探针注册（按 probe_id）。
func (s *Store) UpsertProbe(p *model.Probe) error {
	now := time.Now()
	_, err := s.db.Exec(`INSERT INTO probes(probe_id,name,location,last_seen,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(probe_id) DO UPDATE SET name=excluded.name, location=excluded.location, last_seen=excluded.last_seen`,
		p.ProbeID, p.Name, p.Location, p.LastSeen, now)
	return err
}

// ListProbes 查询全部探针。
func (s *Store) ListProbes() ([]model.Probe, error) {
	rows, err := s.db.Query(`SELECT probe_id,name,location,last_seen,created_at FROM probes ORDER BY location, probe_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Probe
	for rows.Next() {
		var p model.Probe
		if err := rows.Scan(&p.ProbeID, &p.Name, &p.Location, &p.LastSeen, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProbeByID 按 probe_id 查询（不存在返回 nil）。
func (s *Store) ProbeByID(id string) (*model.Probe, error) {
	var p model.Probe
	err := s.db.QueryRow(`SELECT probe_id,name,location,last_seen,created_at FROM probes WHERE probe_id=?`, id).
		Scan(&p.ProbeID, &p.Name, &p.Location, &p.LastSeen, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// DeleteProbe 删除探针注册。
func (s *Store) DeleteProbe(id string) error {
	_, err := s.db.Exec(`DELETE FROM probes WHERE probe_id=?`, id)
	return err
}

// ---------- 资产台账（V1.7） ----------

const ledgerColumns = `id,ip,mac,hostname,os,department,owner,location,description,batch,created_at`

// ReplaceLedger 全量替换台账（导入语义：一次导入 = 一份权威台账快照）。
// 使用事务保证"要么全换、要么不动"，避免导入中途失败留下半份台账。
func (s *Store) ReplaceLedger(entries []model.LedgerEntry) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM ledger`); err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO ledger(ip,mac,hostname,os,department,owner,location,description,batch,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().UTC()
	n := 0
	for i := range entries {
		e := &entries[i]
		if _, err := stmt.Exec(e.IP, e.MAC, e.Hostname, e.OS, e.Department, e.Owner, e.Location, e.Description, e.Batch, now); err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

// ListLedger 返回全部台账条目（按 IP 排序）。
func (s *Store) ListLedger() ([]model.LedgerEntry, error) {
	rows, err := s.db.Query(`SELECT ` + ledgerColumns + ` FROM ledger ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.LedgerEntry
	for rows.Next() {
		var e model.LedgerEntry
		if err := rows.Scan(&e.ID, &e.IP, &e.MAC, &e.Hostname, &e.OS, &e.Department,
			&e.Owner, &e.Location, &e.Description, &e.Batch, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearLedger 清空台账，返回删除条数。
func (s *Store) ClearLedger() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM ledger`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- 分页 ----------

// applyPage 给查询追加 LIMIT/OFFSET。
//
// limit<=0 且 offset<=0 时原样返回（内部/测试需要全量）。
// 只给 offset 不给 limit 时用 `LIMIT -1`——SQLite 语法要求 OFFSET 必须跟在 LIMIT 后面，
// 这不是"不限量"以外的任何语义，别误读成负数限制。
func applyPage(q string, args []any, limit, offset int) (string, []any) {
	if limit <= 0 && offset <= 0 {
		return q, args
	}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	} else {
		q += " LIMIT -1"
	}
	if offset > 0 {
		q += " OFFSET ?"
		args = append(args, offset)
	}
	return q, args
}

// DeleteEventsBefore 清理早于 cutoff 的事件，返回删除条数。
//
// onlyResolved=true 时只删已处置（confirmed / false_positive / deferred）的事件：
// 保留期到了但没人处置的告警不能静默消失——那等于把"没看见"变成"不存在"。
func (s *Store) DeleteEventsBefore(cutoff time.Time, onlyResolved bool) (int64, error) {
	q := `DELETE FROM events WHERE created_at < ?`
	if onlyResolved {
		q += ` AND status <> 'pending'`
	}
	res, err := s.db.Exec(q, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
