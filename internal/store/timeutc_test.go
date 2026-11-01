package store

// dbx / txx / stmtx 三层包装的直接用例。
//
// 为什么单独测这层、而不是只靠调用方（UpsertPort 等）间接覆盖：
// 1.7.0 的正确性完全建立在这三个类型上——**任何一个方法漏掉 normArgs，
// 就有一条写入路径在悄悄用本地时区**。而"漏一个"这件事靠肉眼读代码看不出来
// （`stmtx.QueryRow` 和 `dbx.QueryRow` 长得一模一样），只能逐个方法钉住。
//
// 真实教训：1.7.0 初版只覆盖了 dbx/txx 的 Exec，漏了 Prepare，
// 结果单条写入是 UTC、批量写入（tx.Prepare + stmt.Exec）是本地时区，
// 两种表示混回同一张表，窗口边界重新偏 8 小时。见 TestAllWritePathsStoreUTC。

import (
	"database/sql"
	"testing"
	"time"
)

// utcTestTime 返回一个带 +08:00 偏移的时间，并断言它确实带偏移。
//
// 用固定时区而不是 time.Local：CI runner 多半是 UTC，用 Local 构造出来的时间
// 本来就没有偏移，用例会在 CI 上"通过"但什么都没验。
func utcTestTime(t *testing.T) (time.Time, string) {
	t.Helper()
	cst := time.FixedZone("CST", 8*3600)
	ts := time.Date(2026, 6, 7, 9, 10, 11, 0, cst)
	if off := ts.Format("Z07:00"); off != "+08:00" {
		t.Fatalf("构造失败：时间偏移是 %s，用例失去意义", off)
	}
	return ts, "2026-06-07 01:10:11 +0000 UTC"
}

// TestNormArg 逐个分支钉住参数归一化。
func TestNormArg(t *testing.T) {
	ts, want := utcTestTime(t)

	// 值类型
	if got := normArg(ts); !isUTCValuer(t, got, want) {
		t.Fatalf("time.Time 没被归一化: %#v", got)
	}
	// 指针类型
	if got := normArg(&ts); !isUTCValuer(t, got, want) {
		t.Fatalf("*time.Time 没被归一化: %#v", got)
	}
	// nil 指针必须保持 nil，不能被解引用崩掉
	var nilTime *time.Time
	if got := normArg(nilTime); got != nil {
		t.Fatalf("nil *time.Time 应保持 nil，实际 %#v", got)
	}
	// 命名参数要递归进去
	named := normArg(sql.Named("ts", ts))
	na, ok := named.(sql.NamedArg)
	if !ok {
		t.Fatalf("sql.NamedArg 没有被保留: %#v", named)
	}
	if !isUTCValuer(t, na.Value, want) {
		t.Fatalf("sql.NamedArg 内部的时间没被归一化: %#v", na.Value)
	}
	// 非时间参数原样返回（不要顺手把 int 包一层）
	if got := normArg(42); got != 42 {
		t.Fatalf("非时间参数被改动: %#v", got)
	}
	if got := normArg("x"); got != "x" {
		t.Fatalf("非时间参数被改动: %#v", got)
	}
}

// isUTCValuer 断言参数是 utcValue 且其 Value() 是期望的 UTC 文本。
func isUTCValuer(t *testing.T, v any, want string) bool {
	t.Helper()
	uv, ok := v.(utcValue)
	if !ok {
		return false
	}
	got, err := uv.Value()
	if err != nil {
		t.Fatalf("Value() 报错: %v", err)
	}
	if got != want {
		t.Fatalf("UTC 文本是 %q，期望 %q", got, want)
	}
	return true
}

// TestNormArgsFastPath 不含时间参数时**不得复制切片**。
//
// 这不是微优化洁癖：ports / sessions 的批量写入是高频路径，
// 每批几十个参数，凭空多一次分配会被乘以轮次。更要紧的是"不复制"意味着
// 绝不能就地改写调用方的切片——下面同时钉住这一点。
func TestNormArgsFastPath(t *testing.T) {
	args := []any{"a", 1, 2.5, true}
	out := normArgs(args)
	if len(out) != len(args) {
		t.Fatalf("长度变了: %d → %d", len(args), len(out))
	}
	// 同一个底层数组 → 没复制
	if &out[0] != &args[0] {
		t.Fatal("不含时间参数时不该复制切片（高频写入路径会多一次分配）")
	}

	ts, _ := utcTestTime(t)
	withTime := []any{"a", ts}
	copied := normArgs(withTime)
	if len(copied) != 2 {
		t.Fatalf("长度变了: %d", len(copied))
	}
	if &copied[0] == &withTime[0] {
		t.Fatal("含时间参数时必须复制，否则会就地改写调用方的切片")
	}
	// 调用方的切片必须保持原样
	if _, stillTime := withTime[1].(time.Time); !stillTime {
		t.Fatalf("调用方切片被就地改写了: %#v", withTime[1])
	}
}

// TestWrapperEveryMethodStoresUTC 把三层包装的每个方法各走一遍，逐行断言落库形态。
//
// 断言的是**库里的字节**（CAST(... AS TEXT)），不是读回来的 time.Time：
// 驱动读回时会做一次归一化，看那个会把"没写对"看成"写对了"。
func TestWrapperEveryMethodStoresUTC(t *testing.T) {
	st, err := Open(t.TempDir() + "/wrapper.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	ts, want := utcTestTime(t)
	db := st.db

	if _, err := db.Exec(`CREATE TABLE t_utc (id INTEGER PRIMARY KEY, ts DATETIME, note TEXT)`); err != nil {
		t.Fatalf("建表失败: %v", err)
	}

	// 每条路径插一行，note 记路径名。insert 断言"写对"，select 断言"读时也归一化"。
	type path struct {
		note string
		ins  func(note string) error
		sel  func() error // 用时间做查询条件，验证 Query/QueryRow 的参数也被归一化
	}

	var paths []path

	// 1) db.Exec / db.Query / db.QueryRow
	paths = append(paths, path{
		note: "db.Exec",
		ins: func(note string) error {
			_, err := db.Exec(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`, ts, note)
			return err
		},
		sel: func() error {
			rows, err := db.Query(`SELECT note FROM t_utc WHERE ts >= ? AND ts <= ?`, ts, ts)
			if err != nil {
				return err
			}
			defer rows.Close()
			return drainRows(rows)
		},
	})

	// 2) db.Prepare → stmtx.Exec
	paths = append(paths, path{
		note: "db.Prepare/Exec",
		ins: func(note string) error {
			s, err := db.Prepare(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`)
			if err != nil {
				return err
			}
			defer s.Close()
			_, err = s.Exec(ts, note)
			return err
		},
		sel: func() error {
			s, err := db.Prepare(`SELECT note FROM t_utc WHERE ts >= ? AND ts <= ?`)
			if err != nil {
				return err
			}
			defer s.Close()
			rows, err := s.Query(ts, ts)
			if err != nil {
				return err
			}
			defer rows.Close()
			return drainRows(rows)
		},
	})

	// 3) stmtx.QueryRow
	paths = append(paths, path{
		note: "stmtx.QueryRow",
		ins: func(note string) error {
			_, err := db.Exec(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`, ts, note)
			return err
		},
		sel: func() error {
			s, err := db.Prepare(`SELECT note FROM t_utc WHERE ts >= ? ORDER BY id LIMIT 1`)
			if err != nil {
				return err
			}
			defer s.Close()
			var got string
			return s.QueryRow(ts).Scan(&got)
		},
	})

	// 4) 事务：tx.Exec / tx.Query / tx.QueryRow
	paths = append(paths, path{
		note: "txx.Exec",
		ins: func(note string) error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`, ts, note); err != nil {
				_ = tx.Rollback()
				return err
			}
			var probe string
			if err := tx.QueryRow(`SELECT note FROM t_utc WHERE ts >= ? ORDER BY id LIMIT 1`, ts).Scan(&probe); err != nil {
				_ = tx.Rollback()
				return err
			}
			rows, err := tx.Query(`SELECT note FROM t_utc WHERE ts >= ? AND ts <= ?`, ts, ts)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			err = drainRows(rows)
			rows.Close()
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			return tx.Commit()
		},
	})

	// 5) 事务内预编译：tx.Prepare → stmtx.Exec / Query / QueryRow
	paths = append(paths, path{
		note: "txx.Prepare",
		ins: func(note string) error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			s, err := tx.Prepare(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if _, err := s.Exec(ts, note); err != nil {
				s.Close()
				_ = tx.Rollback()
				return err
			}
			s.Close()
			q, err := tx.Prepare(`SELECT note FROM t_utc WHERE ts >= ? AND ts <= ?`)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			rows, err := q.Query(ts, ts)
			if err != nil {
				q.Close()
				_ = tx.Rollback()
				return err
			}
			err = drainRows(rows)
			rows.Close()
			q.Close()
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			var probe string
			if err := tx.QueryRow(`SELECT note FROM t_utc WHERE ts >= ? ORDER BY id LIMIT 1`, ts).Scan(&probe); err != nil {
				_ = tx.Rollback()
				return err
			}
			return tx.Commit()
		},
	})

	// 6) 命名参数
	paths = append(paths, path{
		note: "NamedArg",
		ins: func(note string) error {
			_, err := db.Exec(`INSERT INTO t_utc (ts, note) VALUES (:ts, :note)`,
				sql.Named("ts", ts), sql.Named("note", note))
			return err
		},
	})

	// 7) *time.Time（非 nil）
	paths = append(paths, path{
		note: "ptr",
		ins: func(note string) error {
			_, err := db.Exec(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`, &ts, note)
			return err
		},
	})

	// 8) nil *time.Time 必须落成 NULL（而不是零值时间或报错）
	paths = append(paths, path{
		note: "nil",
		ins: func(note string) error {
			var nilTime *time.Time
			_, err := db.Exec(`INSERT INTO t_utc (ts, note) VALUES (?, ?)`, nilTime, note)
			return err
		},
	})

	for _, p := range paths {
		if err := p.ins(p.note); err != nil {
			t.Fatalf("%s 写入失败: %v", p.note, err)
		}
		if p.sel != nil {
			if err := p.sel(); err != nil {
				t.Fatalf("%s 用时间做条件查询失败: %v", p.note, err)
			}
		}
	}

	// 逐行断言库里的字节
	rows, err := db.Query(`SELECT CAST(ts AS TEXT), note FROM t_utc ORDER BY id`)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var raw sql.NullString
		var note string
		if err := rows.Scan(&raw, &note); err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		seen[note] = true
		if note == "nil" {
			if raw.Valid {
				t.Fatalf("nil *time.Time 应落成 NULL，实际 %q", raw.String)
			}
			continue
		}
		if !raw.Valid {
			t.Fatalf("%s：时间列是 NULL，参数没传进去", note)
		}
		if raw.String != want {
			t.Fatalf("%s：库里是 %q，期望 %q（这条路径绕过了参数归一化）", note, raw.String, want)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if !seen[p.note] {
			t.Fatalf("%s 这条路径没写进去，用例没覆盖到", p.note)
		}
	}
}

// drainRows 把结果集读干净（顺便确认 Scan 不报错），返回第一个错误。
func drainRows(rows *sql.Rows) error {
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
	}
	return rows.Err()
}
