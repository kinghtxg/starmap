package api

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

// parseCSV 去掉 BOM 后按标准 CSV 解析。
func parseCSV(t *testing.T, body []byte) [][]string {
	t.Helper()
	raw := bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v\n原文: %q", err, string(body))
	}
	return rows
}

// TestCSVExportShapeAndBOM 导出必须有 BOM、表头正确、行数对得上。
//
// BOM 不是可选项：中文 Windows 的 Excel 对无 BOM 的 UTF-8 CSV 按 GBK 解码，
// 整列资产名变乱码——而"用 Excel 打开"是这类文件唯一的使用方式。
func TestCSVExportShapeAndBOM(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	if err := st.UpsertPort(&model.PortRecord{
		NodeKey: "ip:10.0.0.1", IP: "10.0.0.1", Port: 8080, Proto: "tcp",
		Service: "http", State: "open", Source: "probe",
		Product: "泛微 e-cology", Title: "协同管理平台",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, h, http.MethodGet, "/api/export/ports.csv", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type 不符: %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "starmap-ports-") {
		t.Fatalf("Content-Disposition 不符: %q", cd)
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("缺少 UTF-8 BOM，中文 Excel 打开会乱码")
	}

	rows := parseCSV(t, w.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("应 1 行表头 + 1 行数据，实际 %d 行: %#v", len(rows), rows)
	}
	if rows[0][0] != "IP" || rows[0][1] != "端口" {
		t.Fatalf("表头不符: %#v", rows[0])
	}
	if rows[1][0] != "10.0.0.1" || rows[1][1] != "8080" {
		t.Fatalf("数据行不符: %#v", rows[1])
	}
	// 中文必须原样保留（没被转义成 \uXXXX 或 mojibake）
	if rows[1][6] != "泛微 e-cology" {
		t.Fatalf("中文产品名被破坏: %q", rows[1][6])
	}
}

// TestCSVFormulaInjectionGuarded 以 = + - @ 开头的外部内容必须被中和。
//
// 页面标题直接来自被扫描主机返回的 <title>——也就是说，**被扫描的那台机器
// 决定我们导出文件里的内容**。这不只是"数据脏"，是实打实的公式注入：
// 扫到一台返回 `=cmd|'/c calc'!A0` 标题的设备，分析师一打开表格就执行了。
func TestCSVFormulaInjectionGuarded(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	payloads := []struct {
		title string
	}{
		{"=cmd|'/c calc'!A0"},
		{"+1+1"},
		{"@SUM(A1:A9)"},
		{"-2+3"},
	}
	now := time.Now()
	for i, p := range payloads {
		if err := st.UpsertPort(&model.PortRecord{
			NodeKey: "ip:10.0.0." + string(rune('1'+i)),
			IP:      "10.0.0." + string(rune('1'+i)),
			Port:    80 + i, Proto: "tcp", Service: "http", State: "open", Source: "probe",
			Title: p.title, FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	w := doReq(t, h, http.MethodGet, "/api/export/ports.csv", nil, nil)
	rows := parseCSV(t, w.Body.Bytes())
	if len(rows) != len(payloads)+1 {
		t.Fatalf("行数不符: %d", len(rows))
	}
	for i, p := range payloads {
		cell := rows[i+1][8] // 页面标题列
		if strings.HasPrefix(cell, "=") || strings.HasPrefix(cell, "+") ||
			strings.HasPrefix(cell, "@") || strings.HasPrefix(cell, "-") {
			t.Fatalf("公式注入未中和: %q（原文 %q）", cell, p.title)
		}
		if !strings.HasPrefix(cell, "'") {
			t.Fatalf("应在危险字符前加单引号: %q", cell)
		}
		// 内容本身不能被截断，否则分析师看不到原始标题
		if !strings.Contains(cell, strings.TrimPrefix(p.title, p.title[:1])) {
			t.Fatalf("中和后内容丢失: %q", cell)
		}
	}
}

// TestCSVNumberNotQuoted 纯数字/负数不该被加单引号。
//
// 端口号、字节数这类列一旦变成文本，下游脚本 `sum()` 直接算错，
// 而表格里看不出任何异常。
func TestCSVNumberNotQuoted(t *testing.T) {
	cases := map[string]string{
		"8080": "8080",
		"-1":   "-1",
		"-3.5": "-3.5",
		"+1e3": "+1e3", // ParseFloat 认，属数值
		"=1+1": "'=1+1",
		"@abc": "'@abc",
		"正常文本": "正常文本",
		"":     "",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Fatalf("csvSafe(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestExportAssetsAndEvents 资产/事件导出可用（表头 + 数据行）。
func TestExportAssetsAndEvents(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	now := time.Now()
	if _, err := st.SyncAssetsFromNodes([]model.Node{
		{NodeKey: "ip:10.0.0.9", IPs: []string{"10.0.0.9"}, MAC: "aa:bb:cc:dd:ee:ff",
			FirstSeen: now, LastSeen: now},
	}, now); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, h, http.MethodGet, "/api/export/assets.csv", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("资产导出状态码 %d", w.Code)
	}
	rows := parseCSV(t, w.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("资产导出行数不符: %d", len(rows))
	}
	if rows[1][0] != "10.0.0.9" {
		t.Fatalf("资产 IP 不符: %#v", rows[1])
	}
	// 未归档资产的状态列要中文化，不然导出给业务方看不懂 unarchived
	if rows[1][4] != "未归档" {
		t.Fatalf("状态未中文化: %q", rows[1][4])
	}

	// 事件表为空时也要有表头（否则前端无从判断"确实没有事件"）
	w = doReq(t, h, http.MethodGet, "/api/export/events.csv", nil, nil)
	rows = parseCSV(t, w.Body.Bytes())
	if len(rows) != 1 {
		t.Fatalf("空事件表应只有表头，实际 %d 行", len(rows))
	}
}

// TestExportTasksCSV 任务账导出。
func TestExportTasksCSV(t *testing.T) {
	h, st, _ := newTaskRouter(t)
	seedTask(t, st, "t-export", "done", time.Now())
	w := doReq(t, h, http.MethodGet, "/api/export/tasks.csv", nil, nil)
	rows := parseCSV(t, w.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("行数不符: %d", len(rows))
	}
	if rows[1][0] != "t-export" {
		t.Fatalf("任务 ID 不符: %#v", rows[1])
	}
}

// TestExportConcurrencyGuard 导出名额满时要回 429，而不是无限并发放行。
//
// 十个并发导出就是十份全表扫描同时压 SQLite；导出本身不占锁，
// 没有这个名额，一次误操作开十个标签页就能把巡检拖到打不开。
func TestExportConcurrencyGuard(t *testing.T) {
	h, _, srv := newTaskRouter(t)
	if srv.exportSem == nil {
		t.Fatal("exportSem 未初始化，并发守卫没有生效")
	}

	// 手动占满名额，模拟"已有 2 个导出在跑"
	for i := 0; i < exportConcurrency; i++ {
		srv.exportSem <- struct{}{}
	}
	w := doReq(t, h, http.MethodGet, "/api/export/assets.csv", nil, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("名额已满应回 429，实际 %d", w.Code)
	}
	// 429 也要是可读的中文提示，前端直接 toast 出去
	if !strings.Contains(w.Body.String(), "导出过多") {
		t.Fatalf("429 提示不可读: %s", w.Body.String())
	}

	// 释放一个名额后必须恢复正常——守卫只该挡住并发，不该永久锁死
	<-srv.exportSem
	w = doReq(t, h, http.MethodGet, "/api/export/assets.csv", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("释放名额后应 200，实际 %d", w.Code)
	}
	// 名额要还回去，否则跑几次就把自己锁死。
	// 此刻我们手动占着 exportConcurrency-1 个，请求自己那一个必须已经归还。
	if len(srv.exportSem) != exportConcurrency-1 {
		t.Fatalf("名额未归还，剩余 %d（应为 %d）", len(srv.exportSem), exportConcurrency-1)
	}
}
