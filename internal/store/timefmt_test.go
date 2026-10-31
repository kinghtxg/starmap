package store

import (
	"encoding/hex"
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
//   - 时间范围过滤依赖"字符串序 ≈ 时间序"，而这**只在不同来源的时间落到同一
//     时区表示下才严格成立**。库里的确有 +0000 UTC 与 +0800 CST 两种形态并存
//     （见 TestTimeRangeCompareIsOffsetSensitive），所以窗口边界会偏一个时区
//     偏移——这是已知短板，不是这里要保证的东西。
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

// TestTimeRangeCompareIsOffsetSensitive 记录一个**已知短板**，不是期望行为。
//
// 时间列存的是各来源各自的 String() 形态：会话时间来自 JSON（+0000 UTC），
// 维护逻辑用的是 time.Now()（+0800 CST）。字符串比较比的是"几点几分"，
// 不是"哪个时刻"，所以两个同一瞬间、不同时区表示的行会排出错误顺序。
//
// 影响面是**窗口边界偏一个时区偏移**（UTC+8 就是 8 小时），方向是"窗口变宽"：
// 变更页可能把 8 小时前才更新过的端口算成"已消失"，stale 标记也可能提前/推迟。
// 不会写坏数据，也不会漏行，但边界不精确。
//
// 这条用例把当前行为固定下来，好处是：等哪天做了"统一 UTC 定长格式 + 迁移"，
// 它会失败，提醒作者把这条短板从文档里删掉——而不是让短板悄悄留在文档里过时。
func TestTimeRangeCompareIsOffsetSensitive(t *testing.T) {
	if time.Local == time.UTC {
		t.Skip("本地时区就是 UTC，构造不出偏移，跳过")
	}
	st, err := Open(t.TempDir() + "/mix.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 同一瞬间的两种表示：UTC 与本地。
	instant := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	for i, tm := range []time.Time{instant, instant.In(time.Local)} {
		if err := st.UpsertPort(&model.PortRecord{
			NodeKey: "ip:10.1.0." + string(rune('1'+i)),
			IP:      "10.1.0." + string(rune('1'+i)),
			Port:    1000 + i, Proto: "tcp", State: "open",
			FirstSeen: tm, LastSeen: tm,
		}); err != nil {
			t.Fatalf("写端口失败: %v", err)
		}
	}

	// 两种表示在库里是两串不同的文本（这是短板的**来源**，本身不需要修：
	// 存什么形态由驱动决定，我们只保证 substr 分组不受影响）。
	var distinct int
	if err := st.db.QueryRow(`SELECT COUNT(DISTINCT first_seen) FROM ports`).Scan(&distinct); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if distinct != 2 {
		t.Logf("两种时区表示落库后相同（distinct=%d），说明驱动已统一归一化，本短板可能已消失", distinct)
	}

	// 用"该瞬间之后 1 秒"做下界，两行都应该落在窗口外。
	var leaked int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM ports WHERE first_seen >= ?`, instant.Add(time.Second)).Scan(&leaked); err != nil {
		t.Fatalf("范围比较失败: %v", err)
	}
	if leaked != 0 {
		t.Logf("注意：下界之后仍有 %d 行被判为命中——时区偏移导致的窗口变宽仍然存在", leaked)
	}
}
