package store

// timeCols 清单的元测试。
//
// 1.7.0 把"时间一律存 UTC"建在两层上：写入口归一化（dbx/txx/stmtx）+ 存量迁移
// （timeCols 逐列转）。第二层是一个**手写清单**，而手写清单一律会漏——
// 这一版就漏了 site_meta.updated_at（新加的表，还专门为它建了倒序索引）。
//
// 漏了不会报错：normalizeColumn 对不存在的列/表只会静默 continue，
// 效果是老数据继续带本地偏移，与新数据混在同一列里，窗口边界偏 8 小时。
// 症状是"某些行查不出来"，而查询本身永远返回 200。
//
// 所以这条用例不测行为，测的是**清单与 schema 的一致性**：
// 加新表的人忘了补清单，CI 会在这里拦住。

import (
	"sort"
	"strings"
	"testing"
)

// schemaDateTimes 反查库里所有声明为 DATETIME/TIMESTAMP 的列。
func schemaDateTimes(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	// pragma_table_info 是表值函数，能跟着 sqlite_master 走一遍所有表。
	// 排除 sqlite_ 前缀的内部表（sqlite_sequence 之类没有时间列，但一并挡掉更省心）。
	rows, err := st.db.Query(`
		SELECT m.name AS tbl, p.name AS col
		FROM sqlite_master m
		JOIN pragma_table_info(m.name) p
		WHERE m.type = 'table'
		  AND m.name NOT LIKE 'sqlite_%'
		  AND (UPPER(p.type) LIKE '%DATETIME%' OR UPPER(p.type) LIKE '%TIMESTAMP%')
		ORDER BY m.name, p.name`)
	if err != nil {
		t.Fatalf("反查 schema 时间列失败: %v", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		out[tbl+"."+col] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("一个时间列都没查到，反查语句本身失效了（用例会变成永远通过）")
	}
	return out
}

// TestTimeColsCoversAllSchemaDateTimes 清单必须与 schema 双向一致。
func TestTimeColsCoversAllSchemaDateTimes(t *testing.T) {
	st, err := Open(t.TempDir() + "/timecols.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	schema := schemaDateTimes(t, st)

	listed := map[string]bool{}
	for _, tc := range timeCols {
		for _, c := range tc.cols {
			listed[tc.table+"."+c] = true
		}
	}

	// 方向一：schema 里有、清单里没有 → 老数据永远不会被归一化
	var missing []string
	for k := range schema {
		if !listed[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("这些时间列没进 timeCols，存量数据会保持旧时区：%v\n"+
			"（在 internal/store/timeutc.go 的 timeCols 里补上）", missing)
	}

	// 方向二：清单里有、schema 里没有 → 迁移永远静默失败（normalizeColumn 会 continue）
	var bogus []string
	for k := range listed {
		if !schema[k] {
			bogus = append(bogus, k)
		}
	}
	sort.Strings(bogus)
	if len(bogus) > 0 {
		t.Fatalf("timeCols 里有 schema 中不存在的列（迁移会静默跳过）：%v", strings.Join(bogus, ", "))
	}
}
