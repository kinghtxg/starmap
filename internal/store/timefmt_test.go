package store

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// TestTimeStorageFormat 锁定 DATETIME 列在库里的文本形态。
//
// 这不是"实现细节测试"，而是趋势页/变更页能否按天分组的前提。实测结论：
// modernc.org/sqlite 把 time.Time 绑成 **RFC3339**（`2026-03-04T15:04:05.12+08:00`，
// 带 T、带纳秒、带本地偏移），而 SQLite 内置的 date()/strftime() 只认
// `YYYY-MM-DD HH:MM:SS`（**空格**分隔）。
//
// 后果不是报错，而是**静默返回 NULL**：`SELECT date(first_seen) GROUP BY 1`
// 会把所有行分进同一个 NULL 桶，趋势图画出来是一条平线、变更页显示"0 条"，
// 而接口 200、日志无异常。这条测试就是为了把这件事钉死——
// 按天分组一律用 substr(col,1,10)，不要用 date()。
func TestTimeStorageFormat(t *testing.T) {
	st, err := Open(t.TempDir() + "/fmt.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 固定时刻，含非零时分秒与本地时区，最能暴露格式差异。
	ts := time.Date(2026, 3, 4, 15, 4, 5, 123456789, time.Local)
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.0.0.1", IP: "10.0.0.1", Port: 80, Proto: "tcp",
		Service: "http", State: "open", Source: "probe",
		FirstSeen: ts, LastSeen: ts,
	}); err != nil {
		t.Fatalf("写端口失败: %v", err)
	}

	var raw string
	if err := st.db.QueryRow(`SELECT first_seen FROM ports LIMIT 1`).Scan(&raw); err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if len(raw) < 19 || raw[4] != '-' || raw[7] != '-' || raw[10] != 'T' {
		t.Fatalf("DATETIME 存储形态变了，按天分组/时间比较都要重新验证: %q", raw)
	}
	if raw[:10] != "2026-03-04" {
		t.Fatalf("日期前缀不是 YYYY-MM-DD: %q", raw)
	}

	// 钉住这个坑：date() 吃不了 RFC3339，返回 NULL。
	// 哪天驱动换成空格分隔的形态，这条断言会失败，提醒把分组方式改回去。
	var nullable *string
	if err := st.db.QueryRow(`SELECT date(first_seen) FROM ports LIMIT 1`).Scan(&nullable); err != nil {
		t.Fatalf("date() 查询本身出错: %v", err)
	}
	if nullable != nil {
		t.Logf("注意：date() 现在能解析了（%q），按天分组可以简化，但 substr 仍然正确", *nullable)
	}

	// substr 是唯一稳定的按天分组方式。
	var day string
	if err := st.db.QueryRow(`SELECT substr(first_seen,1,10) FROM ports LIMIT 1`).Scan(&day); err != nil {
		t.Fatalf("substr 分组失败: %v", err)
	}
	if day != "2026-03-04" {
		t.Fatalf("substr 分组结果不符: %q", day)
	}

	// 时间范围过滤依赖"同一偏移下字符串序 == 时间序"。
	// 中文区部署无夏令时，这个假设成立；跨时区迁移历史数据不在支持范围内。
	var inRange int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM ports WHERE first_seen >= ? AND first_seen < ?`,
		ts.Add(-time.Hour), ts.Add(time.Hour)).Scan(&inRange); err != nil {
		t.Fatalf("范围比较失败: %v", err)
	}
	if inRange != 1 {
		t.Fatalf("时间范围比较失效（返回 %d 行），保留期清理与变更页都会一起坏掉", inRange)
	}
}
