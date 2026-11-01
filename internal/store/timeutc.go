package store

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---------- 为什么需要这一层（1.7.0） ----------
//
// modernc.org/sqlite 把 time.Time 参数序列化成 **time.Time.String()**：
//
//	"2026-03-04 15:04:05.123456789 +0800 CST"
//
// 注意这里存的是"带时区偏移的本地时间文本"，而所有时间范围查询
// （变更视图、趋势、端口 stale、会话回收）都是**字符串比较**。
// 文本比较比的是"几点几分"，不是"哪个时刻"：
//
//	同一瞬间的两条记录
//	  A = "2026-03-04 15:00:00 +0800 CST"   （15:00 北京时间）
//	  B = "2026-03-04 08:00:00 +0000 UTC"   （08:00 UTC，其实晚 1 小时）
//	A < B？按文本 '15' > '08' → 假。按时刻 A 其实**早** 1 小时 → 真。
//
// 后果是时间窗口边界会偏一个时区偏移（UTC+8 即 8 小时），方向是多算不漏行，
// 所以功能上看不出来——这正是它值得单独修的原因。
//
// 修法不是逐个查询改 SQL（那样每加一个查询就得记得改一次），而是**在写入口
// 归一化**：所有写进库的时间一律转成 UTC，文本就自带 "+0000 UTC"，
// 于是"文本序 == 时刻序"重新成立，历史查询一行都不用动。
//
// 为什么用 driver.Valuer 而不是在调用点写 .UTC()：调用点有近百处，漏一处就是
// 一颗埋着的雷；Valuer 由 database/sql 在**参数下发给驱动之前**求值，
// 无论走 Exec / Query / QueryRow / 事务 / 预编译语句，都会被拦到。

// utcValue 把时间绑成 UTC 文本。刻意返回 string 而不是 time.Time，
// 否则驱动又会调 .String() 把时区带回来。
type utcValue struct{ t time.Time }

// Value 实现 driver.Valuer。
func (u utcValue) Value() (driver.Value, error) {
	return u.t.UTC().String(), nil
}

// normArg 把单个参数里的时间转成 UTC。
func normArg(a any) any {
	switch v := a.(type) {
	case time.Time:
		return utcValue{v}
	case *time.Time:
		if v == nil {
			return nil
		}
		return utcValue{*v}
	case sql.NamedArg:
		v.Value = normArg(v.Value)
		return v
	}
	return a
}

// normArgs 只有在真的含时间参数时才复制切片，避免给高频写入路径凭空加一次分配。
func normArgs(a []any) []any {
	need := false
	for _, v := range a {
		switch v.(type) {
		case time.Time, *time.Time, sql.NamedArg:
			need = true
		}
		if need {
			break
		}
	}
	if !need {
		return a
	}
	out := make([]any, len(a))
	for i, v := range a {
		out[i] = normArg(v)
	}
	return out
}

// execer 是 *sql.DB / *sql.Tx / 本文件几个包装类型共有的最小集合。
// 抽出来是为了让"既能接连接、也能接事务"的辅助函数不必写两遍。
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// 编译期断言：连接与事务的包装必须保持与原类型相同的调用形状。
// 哪天 sql 库给 Exec 加了新签名，这里会先炸，而不是等到某个 handler 运行期报错。
//
// *stmtx 不在此列：预编译语句的 Exec 签名是 Exec(args ...any)，不带 query 参数。
// 它单独由 dbx.Prepare/txx.Prepare 的返回值类型钉住。
var (
	_ execer = (*sql.DB)(nil)
	_ execer = (*dbx)(nil)
	_ execer = (*txx)(nil)
)

// dbx 是 *sql.DB 的薄包装：只把参数里的时间归一化，其余方法全部透传。
//
// 用嵌入而不是实现全部方法：*sql.DB 有二十多个方法（Ping / SetMaxOpenConns /
// Conn / Stats …），逐个转发只会制造维护负担，嵌入天然全部继承。
type dbx struct{ *sql.DB }

// Exec 见 execer。
func (d *dbx) Exec(q string, a ...any) (sql.Result, error) { return d.DB.Exec(q, normArgs(a)...) }

// Query 见 execer。
func (d *dbx) Query(q string, a ...any) (*sql.Rows, error) { return d.DB.Query(q, normArgs(a)...) }

// QueryRow 见 execer。
func (d *dbx) QueryRow(q string, a ...any) *sql.Row { return d.DB.QueryRow(q, normArgs(a)...) }

// Begin 开事务。返回的 *txx 同样会归一化参数——事务里的时间如果漏了，
// 恰恰是最难发现的那种（主流程正常、回滚路径带脏数据）。
func (d *dbx) Begin() (*txx, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &txx{tx}, nil
}

// Prepare 预编译语句。返回的 *stmtx 同样会归一化参数。
//
// **这个覆盖是必须的**：预编译语句的 Exec 直接进驱动，
// 不经过 dbx.Exec 的参数处理。实测过一次——批量写端口（UpsertPorts）走的正是
// tx.Prepare + stmt.Exec，于是单条写入是 UTC、批量写入还是本地时区，
// 两种表示又混回了一张表，窗口边界重新偏 8 小时。
func (d *dbx) Prepare(q string) (*stmtx, error) {
	s, err := d.DB.Prepare(q)
	if err != nil {
		return nil, err
	}
	return &stmtx{s}, nil
}

// stmtx 是 *sql.Stmt 的薄包装，理由同 dbx。
type stmtx struct{ *sql.Stmt }

// Exec 见 execer。
func (s *stmtx) Exec(a ...any) (sql.Result, error) { return s.Stmt.Exec(normArgs(a)...) }

// Query 见 execer。
func (s *stmtx) Query(a ...any) (*sql.Rows, error) { return s.Stmt.Query(normArgs(a)...) }

// QueryRow 见 execer。
func (s *stmtx) QueryRow(a ...any) *sql.Row { return s.Stmt.QueryRow(normArgs(a)...) }

// txx 是 *sql.Tx 的薄包装，理由同 dbx。
type txx struct{ *sql.Tx }

// Prepare 预编译语句（理由见 dbx.Prepare）。
func (t *txx) Prepare(q string) (*stmtx, error) {
	s, err := t.Tx.Prepare(q)
	if err != nil {
		return nil, err
	}
	return &stmtx{s}, nil
}

// Exec 见 execer。
func (t *txx) Exec(q string, a ...any) (sql.Result, error) { return t.Tx.Exec(q, normArgs(a)...) }

// Query 见 execer。
func (t *txx) Query(q string, a ...any) (*sql.Rows, error) { return t.Tx.Query(q, normArgs(a)...) }

// QueryRow 见 execer。
func (t *txx) QueryRow(q string, a ...any) *sql.Row { return t.Tx.QueryRow(q, normArgs(a)...) }

// ---------- 存量迁移 ----------

// timeCols 全库时间列清单。加新表/新时间列时要同步补进来，
// 否则老数据会保持旧时区表示，与 UTC 新数据混在一起。
//
// 别靠人记：TestTimeColsCoversAllSchemaDateTimes 会拿 sqlite_master +
// pragma_table_info 反查"库里所有 DATETIME 列"，与这份清单双向比对。
// 漏一列、或写了一个不存在的列名，那条用例都会失败——后者更要紧，
// 因为 normalizeColumn 对不存在的列只会静默 continue，永远看不出问题。
var timeCols = []struct {
	table string
	cols  []string
}{
	{"nodes", []string{"first_seen", "last_seen"}},
	{"edges", []string{"first_seen", "last_seen"}},
	{"sessions", []string{"first_seen", "last_seen"}},
	{"session_offsets", []string{"first_seen", "last_seen"}},
	{"events", []string{"created_at", "updated_at"}},
	{"whitelist", []string{"created_at"}},
	{"audit", []string{"created_at"}},
	{"assets", []string{"first_seen", "last_seen", "archived_at", "created_at", "updated_at"}},
	{"ports", []string{"first_seen", "last_seen"}},
	{"site_meta", []string{"updated_at"}},
	{"probes", []string{"last_seen", "created_at"}},
	{"ledger", []string{"created_at"}},
	{"intel_iocs", []string{"updated_at", "received_at", "expires_at"}},
	{"discover_tasks", []string{"started_at", "finished_at"}},
}

const timeUTCMarker = "schema.time_utc"

// timeLayouts 历史值可能长成什么样。第一项就是 time.Time.String()，
// 第二项是为了吃掉 time.Now() 带的单调时钟尾巴（" m=+0.006953401"）。
var timeLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// parseStoredTime 解析库里的原始时间文本。
func parseStoredTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// 去掉单调时钟后缀："... +0800 CST m=+0.006953401"。
	// 它不是时区信息，留着会让所有布局匹配失败。
	if i := strings.Index(s, " m=+"); i > 0 {
		s = s[:i]
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// normalizeTimeColumns 把存量行的时间文本统一到 UTC。
//
// 为什么必须做：新写入已经是 UTC，老数据还是带本地偏移的文本，
// 两者混在一起比较时窗口边界照样会错——归一化只做一半等于没做。
//
// 用 meta 标记只跑一次：sessions 表在真实环境能有几十万行，
// 每次启动都全表扫一遍是不可接受的。
func normalizeTimeColumns(db *sql.DB) (int, error) {
	var done string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, timeUTCMarker).Scan(&done)
	switch {
	case err == nil && done != "":
		return 0, nil // 已经迁移过
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		// meta 表不存在等异常不该让服务起不来：迁移是"尽力而为"的优化，
		// 失败时按未迁移处理（下一轮启动再试）。
		return 0, nil
	}

	total := 0
	for _, tc := range timeCols {
		for _, col := range tc.cols {
			n, err := normalizeColumn(db, tc.table, col)
			if err != nil {
				// 单列失败不影响其余列；这类失败一般是老库里存了非时间文本。
				continue
			}
			total += n
		}
	}
	_, err = db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
	                  ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		timeUTCMarker, fmt.Sprintf("%d", total))
	return total, err
}

// normalizeColumn 转换一列。返回转换行数。
//
// 按 rowid 游标推进而不是"每批重查一遍过滤条件"：解析不了的值会一直满足
// `NOT LIKE '%+0000 UTC'`，重查式分批会在它身上原地打转（无限循环）。
// 用 rowid 游标，无论本批转没转成功，下一批都从更大的 rowid 开始。
func normalizeColumn(db *sql.DB, table, col string) (int, error) {
	// 已经统一成 UTC 的行直接跳过：文本以 " +0000 UTC" 结尾。
	// CAST 成 TEXT 是为了拿**原始字节**，而不是让驱动先解析成 time.Time
	// 再按 RFC3339 吐出来——那样永远看不出库里到底存的是什么。
	q := fmt.Sprintf(
		`SELECT rowid, CAST(%s AS TEXT) FROM %s
		 WHERE rowid > ? AND %s IS NOT NULL AND CAST(%s AS TEXT) NOT LIKE '%%+0000 UTC'
		 ORDER BY rowid LIMIT ?`,
		col, table, col, col)
	upd := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE rowid = ?`, table, col)

	converted := 0
	var cursor int64
	for {
		rows, err := db.Query(q, cursor, 5000)
		if err != nil {
			return converted, err
		}
		type pair struct {
			id  int64
			raw string
		}
		var batch []pair
		for rows.Next() {
			var p pair
			if err := rows.Scan(&p.id, &p.raw); err != nil {
				rows.Close()
				return converted, err
			}
			batch = append(batch, p)
		}
		rows.Close()
		if len(batch) == 0 {
			return converted, nil
		}
		for _, p := range batch {
			cursor = p.id
			t, ok := parseStoredTime(p.raw)
			if !ok {
				// 解析不了的值（人工改库、第三方写入）原样留着——
				// 静默改成一个猜出来的时刻，比留着更容易查。
				continue
			}
			if _, err := db.Exec(upd, t.UTC().String(), p.id); err != nil {
				return converted, err
			}
			converted++
		}
	}
}
