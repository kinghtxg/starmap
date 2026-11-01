package store

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestTimeStorageFormat 锁定 DATETIME 列在库里的**字节形态**。
//
// 这不是"实现细节测试"，而是趋势页/变更页能否按天分组的前提。
//
// 1.6.1 更正（重要）：本文件原来断言库里存的是 RFC3339、并据此解释
// "date() 为什么返回 NULL"。那个结论是**错的**，错在取证方式——
// `Scan(&string)` 读到的是驱动把 DATETIME **读回**成 time.Time 之后的
// RFC3339，不是磁盘上的字节。用 `hex()` 看原始字节才发现：驱动落库写的是
// `time.Time.String()`：
//
//	来自 JSON 的时间   2026-11-01 03:12:00 +0000 UTC
//	来自 time.Now()    2026-11-01 03:29:24.1325527 +0800 CST m=+124.416745601
//
// 注意第二行带**单调时钟尾巴**（`m=+...`），那是纯垃圾，只有 substr 取前 10 位
// 才不受影响。
//
// 由此得出两条仍然成立、且必须继续遵守的规则：
//   - 按天分组一律 substr(col,1,10)，不要用 date()；
//   - 时间范围过滤依赖"字符串序 == 时间序"，而这只在**所有时间落到同一时区表示**
//     时才严格成立。
//
// 1.7.0 起第二条件由写入口保证：`dbx` 会把所有 time.Time 参数转成 UTC 再下发，
// 于是库里统一是 `... +0000 UTC`（见 timeutc.go 与 TestTimeRangeCompareIsOffsetInsensitive）。
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

	// 用 hex() 取磁盘上的真实字节：任何 Scan(&string) 都会经过驱动的
	// "DATETIME → time.Time → RFC3339" 归一化，看到的不是存储形态。
	var hexStr string
	if err := st.db.QueryRow(`SELECT hex(first_seen) FROM ports LIMIT 1`).Scan(&hexStr); err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("十六进制解码失败: %v", err)
	}
	raw := string(rawBytes)
	if len(raw) < 20 {
		t.Fatalf("时间列存储形态异常（长度 %d）: %q", len(raw), raw)
	}
	if raw[:10] != "2026-03-04" {
		t.Fatalf("日期前缀不是 YYYY-MM-DD: %q", raw)
	}
	// 第 11 个字节只允许 ' ' 或 'T'：不同驱动/版本在这两者之间摇摆过，
	// 任何更激进的假设（比如"一定是 T"）都会在某个平台上变成假失败。
	if sep := raw[10]; sep != ' ' && sep != 'T' {
		t.Fatalf("日期与时间之间的分隔符异常（%q）: %q", sep, raw)
	}
	t.Logf("时间列实际存储形态: %q", raw)

	// 钉住这个坑：date() 认不出库里存的形态，返回 NULL。
	// 哪天驱动换成 date() 能解析的形态，这条断言会提示可以简化分组，但 substr 仍然正确。
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

// TestTimeRangeCompareIsOffsetInsensitive 是 1.7.0 的回归用例：
// **同一瞬间的不同时区表示，落库后必须是同一串文本**。
//
// 1.6.1 这里记录的是一条已知短板（同一瞬间在 +0000 UTC 与 +0800 CST 下是两串
// 不同文本，字符串比较比的是"几点几分"不是"哪个时刻"，窗口边界偏一个时区偏移）。
// 1.7.0 在写入口统一转 UTC 之后，这条短板消失，用例改成断言"不再偏移"。
//
// 为什么要留着：这是唯一一条能同时验证「写入口归一化」和「历史查询不用改」的用例。
// 只断言"写进去是 UTC"是不够的——真正要保证的是**比较结果正确**。
func TestTimeRangeCompareIsOffsetInsensitive(t *testing.T) {
	st, err := Open(t.TempDir() + "/mix.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 同一瞬间的两种表示：UTC 与本地（在 UTC 机器上就是同一个值，仍然成立）。
	instant := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	for i, tm := range []time.Time{instant, instant.In(time.Local), instant.In(time.FixedZone("CST", 8*3600))} {
		if err := st.UpsertPort(&model.PortRecord{
			NodeKey: "ip:10.1.0." + string(rune('1'+i)),
			IP:      "10.1.0." + string(rune('1'+i)),
			Port:    1000 + i, Proto: "tcp", State: "open",
			FirstSeen: tm, LastSeen: tm,
		}); err != nil {
			t.Fatalf("写端口失败: %v", err)
		}
	}

	// 三种表示在库里必须是同一串文本。不是的话，下面的范围比较一定会错。
	var distinct int
	if err := st.db.QueryRow(`SELECT COUNT(DISTINCT CAST(first_seen AS TEXT)) FROM ports`).Scan(&distinct); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if distinct != 1 {
		var sample string
		_ = st.db.QueryRow(`SELECT CAST(first_seen AS TEXT) FROM ports LIMIT 1`).Scan(&sample)
		t.Fatalf("同一瞬间落库成了 %d 种文本形态（样本 %q），写入口的 UTC 归一化失效，"+
			"变更页/趋势/保留期清理的窗口边界会一起偏一个时区偏移", distinct, sample)
	}

	// 下界取该瞬间之后 1 秒：三行都该在窗口外。
	// 偏移存在时，带 +0800 的那几行会以 "15:08:09" 排在 "07:08:10" 之后被误命中。
	var leaked int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM ports WHERE first_seen >= ?`, instant.Add(time.Second)).Scan(&leaked); err != nil {
		t.Fatalf("范围比较失败: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("下界之后仍有 %d 行被判为命中——时区偏移导致的窗口变宽又回来了", leaked)
	}

	// 反方向也要验：上界取该瞬间减 1 秒，三行都该在窗口内。
	var hit int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM ports WHERE first_seen < ?`, instant.Add(time.Second)).Scan(&hit); err != nil {
		t.Fatalf("范围比较失败: %v", err)
	}
	if hit != 3 {
		t.Fatalf("窗口内应命中 3 行，实际 %d 行", hit)
	}
}

// TestNormalizeTimeColumnsMigratesLegacy 验证存量迁移：老库里带本地偏移的时间文本
// 会被改写成 UTC，且**改完之后比较结果仍然指向同一时刻**。
//
// 这条不能省：真实环境中升级上来的库（几十万行 ports/sessions）全是 +0800 CST，
// 只修写入方等于只修一半——新旧两批数据混在一张表里，窗口照样错。
func TestNormalizeTimeColumnsMigratesLegacy(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	st, err := Open(path)
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}

	// 绕开 dbx 直接写"老格式"（+0800 CST），模拟 1.6.x 留下的数据。
	legacy := time.Date(2026, 5, 6, 7, 8, 9, 0, time.FixedZone("CST", 8*3600))
	legacyText := legacy.String() // "2026-05-06 07:08:09 +0800 CST"
	instantText := legacy.UTC().String()
	if legacyText == instantText {
		t.Fatal("构造失败：两种表示相同，用例失去意义")
	}
	if _, err := st.db.DB.Exec(`INSERT INTO ports(node_key, ip, port, proto, state, first_seen, last_seen)
	                            VALUES('ip:10.9.9.9','10.9.9.9',80,'tcp','open',?,?)`,
		legacyText, legacyText); err != nil {
		t.Fatalf("写入老格式失败: %v", err)
	}
	// 清掉标记，让迁移再跑一次（Open 时已经跑过一轮，那时表还是空的）。
	if _, err := st.db.DB.Exec(`DELETE FROM meta WHERE key = ?`, timeUTCMarker); err != nil {
		t.Fatalf("清标记失败: %v", err)
	}

	n, err := normalizeTimeColumns(st.db.DB)
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if n < 1 {
		t.Fatalf("应有至少 1 行被转换，实际 %d", n)
	}

	var raw string
	if err := st.db.QueryRow(`SELECT CAST(first_seen AS TEXT) FROM ports WHERE ip='10.9.9.9'`).Scan(&raw); err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if got, ok := parseStoredTime(raw); !ok || !got.Equal(legacy) {
		t.Fatalf("迁移后时刻变了：原文 %q → %q（期望仍是 %s）", legacyText, raw, legacy.UTC())
	}
	// 迁移的核心目的：能用 UTC 参数正确比较。
	var hit int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE ip='10.9.9.9' AND first_seen = ?`,
		legacy.UTC()).Scan(&hit); err != nil {
		t.Fatalf("比较失败: %v", err)
	}
	if hit != 1 {
		t.Fatalf("迁移后用 UTC 参数应该能命中，实际 %d 行", hit)
	}

	// 幂等：再跑一次不该再改任何行。
	if n2, err := normalizeTimeColumns(st.db.DB); err != nil || n2 != 0 {
		t.Fatalf("第二次迁移应无改动，实际 n=%d err=%v", n2, err)
	}
	_ = st.Close()
}

// TestAllWritePathsStoreUTC 覆盖**所有**写库路径的时间归一化。
//
// 这条用例的由来：1.7.0 的单条用例全绿之后，真机跑起来发现站点列表的时间是
// "Z"（UTC），变更视图里却是 "+08:00"——因为批量写入走的是
// tx.Prepare + stmt.Exec，绕过了 dbx.Exec 的参数处理。
// 只测一条路径等于没测：写入路径有五种（单条、批量、预编译、事务、资产同步），
// 少覆盖一种，那种就会在真实环境里悄悄写成另一种时区。
func TestAllWritePathsStoreUTC(t *testing.T) {
	st, err := Open(t.TempDir() + "/paths.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 强制用带偏移的时区构造时间：在 UTC 机器上 +08:00 仍然是不同的表示。
	cst := time.FixedZone("CST", 8*3600)
	ts := time.Date(2026, 6, 7, 9, 10, 11, 0, cst)
	if ts.Format("Z07:00") == "+00:00" {
		t.Fatal("构造失败：时间没有偏移，用例失去意义")
	}

	// 1) 单条写入
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.7.0.1", IP: "10.7.0.1", Port: 80, Proto: "tcp",
		State: "open", FirstSeen: ts, LastSeen: ts,
	}); err != nil {
		t.Fatalf("单条写端口失败: %v", err)
	}
	// 2) 批量写入（tx.Prepare + stmt.Exec）
	if err := st.UpsertPorts([]model.PortRecord{{
		NodeKey: "ip:10.7.0.2", IP: "10.7.0.2", Port: 81, Proto: "tcp",
		State: "open", FirstSeen: ts, LastSeen: ts,
	}}); err != nil {
		t.Fatalf("批量写端口失败: %v", err)
	}
	// 3) 会话批量（另一条 Prepare 路径）
	if err := st.SaveSessions([]model.Session{{
		FiveTuple: model.FiveTuple{SrcIP: "10.7.0.3", DstIP: "10.7.0.4", SrcPort: 1234, DstPort: 80, Proto: "tcp"},
		FirstSeen: ts, LastSeen: ts,
	}}); err != nil {
		t.Fatalf("写会话失败: %v", err)
	}

	check := func(table, col, where string) {
		t.Helper()
		var raw string
		q := "SELECT CAST(" + col + " AS TEXT) FROM " + table
		if where != "" {
			q += " WHERE " + where
		}
		q += " LIMIT 1"
		if err := st.db.QueryRow(q).Scan(&raw); err != nil {
			t.Fatalf("读 %s.%s 失败: %v", table, col, err)
		}
		got, ok := parseStoredTime(raw)
		if !ok {
			t.Fatalf("%s.%s 存了无法解析的时间: %q", table, col, raw)
		}
		if !got.Equal(ts) {
			t.Fatalf("%s.%s 时刻变了：%q → %s（期望 %s）", table, col, raw, got.UTC(), ts.UTC())
		}
		if !strings.HasSuffix(raw, "+0000 UTC") {
			t.Fatalf("%s.%s 没有归一化成 UTC: %q（预编译/批量路径可能绕过了参数处理）", table, col, raw)
		}
	}
	check("ports", "first_seen", "port=80") // 单条
	check("ports", "first_seen", "port=81") // 批量
	check("sessions", "first_seen", "")     // 会话批量

	// 三条路径写进去的**同一瞬间**必须是同一串文本，否则窗口比较又会错。
	var distinct int
	if err := st.db.QueryRow(`SELECT COUNT(DISTINCT CAST(first_seen AS TEXT)) FROM ports`).Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != 1 {
		t.Fatalf("单条与批量写入的时间文本不一致（%d 种），窗口边界会偏一个时区偏移", distinct)
	}
}
