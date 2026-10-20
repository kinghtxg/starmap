package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"starmap/internal/model"
)

func mustJSON(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("状态码=%d 期望 200，body=%s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("解析响应失败: %v body=%s", err, w.Body.String())
	}
}

// seedAsset 直接写入一台系统已发现的主机（模拟流量/探测已发现，尚未归档）。
func seedAsset(t *testing.T, st interface {
	UpsertAsset(*model.Asset) (int64, error)
}, key, ip, mac string, seen time.Time) {
	t.Helper()
	_, err := st.UpsertAsset(&model.Asset{
		NodeKey: key, IPs: []string{ip}, MAC: mac,
		Status:    model.AssetUnarchived,
		FirstSeen: seen, LastSeen: seen, CreatedAt: seen, UpdatedAt: seen,
	})
	if err != nil {
		t.Fatalf("写入资产失败: %v", err)
	}
}

func TestLedgerImportJSONAndRawCSV(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())

	// 1) JSON 粘贴导入
	csv := "IP地址,MAC地址,主机名,归属单位\n" +
		"10.0.0.11,AA-BB-CC-00-00-11,pc1,办公室\n" +
		"bad-ip,,x,\n" +
		"10.0.0.99,,ghost,机房\n"
	w := doReq(t, h, http.MethodPost, "/api/ledger/import",
		map[string]any{"csv": csv, "batch": "粘贴台账"}, nil)
	var imp struct {
		Imported, Skipped int
		Batch             string
	}
	mustJSON(t, w, &imp)
	if imp.Imported != 2 || imp.Skipped != 1 || imp.Batch != "粘贴台账" {
		t.Fatalf("导入结果不对: %+v", imp)
	}

	// 2) 原始 text/csv 导入（脚本/curl 场景），全量替换语义
	raw := "ip,hostname\n10.0.0.11,pc1\n"
	req := httptest.NewRequest(http.MethodPost, "/api/ledger/import", bytes.NewReader([]byte(raw)))
	req.Header.Set("Content-Type", "text/csv")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var imp2 struct{ Imported int }
	mustJSON(t, rec, &imp2)
	if imp2.Imported != 1 {
		t.Fatalf("原始 CSV 导入条数=%d 期望 1", imp2.Imported)
	}

	// 3) 列表应只剩最新一份（全量替换）
	lw := doReq(t, h, http.MethodGet, "/api/ledger", nil, nil)
	var list struct {
		Entries []model.LedgerEntry
		Total   int
	}
	mustJSON(t, lw, &list)
	if list.Total != 1 || list.Entries[0].IP != "10.0.0.11" {
		t.Fatalf("台账未全量替换: %+v", list)
	}
}

func TestLedgerDiffEndToEnd(t *testing.T) {
	h, st := newTestRouter(t, testCfg())
	now := time.Now().UTC()

	// 台账：.11 在册；.99 是已下线的僵尸记录
	csv := "ip,mac,hostname,department,owner\n" +
		"10.0.0.11,aa:bb:cc:00:00:11,pc1,办公室,张三\n" +
		"10.0.0.99,,old,机房,王五\n"
	if w := doReq(t, h, http.MethodPost, "/api/ledger/import", map[string]any{"csv": csv}, nil); w.Code != 200 {
		t.Fatalf("导入失败: %d %s", w.Code, w.Body.String())
	}

	// 网内实际发现：.11（在册）、.77（台账外的影子设备）、.31 与台账 .13 同 MAC（换 IP）
	seedAsset(t, st, "mac:aa:bb:cc:00:00:11", "10.0.0.11", "aa:bb:cc:00:00:11", now)
	seedAsset(t, st, "mac:aa:bb:cc:00:00:77", "10.0.0.77", "aa:bb:cc:00:00:77", now)
	seedAsset(t, st, "mac:aa:bb:cc:00:00:13", "10.0.0.31", "aa:bb:cc:00:00:13", now)

	// 补一条台账，让 .13 → .31 构成"同机换 IP"
	csv2 := "ip,mac,hostname,department,owner\n" +
		"10.0.0.11,aa:bb:cc:00:00:11,pc1,办公室,张三\n" +
		"10.0.0.13,aa:bb:cc:00:00:13,pc2,办公室,李四\n" +
		"10.0.0.99,,old,机房,王五\n"
	doReq(t, h, http.MethodPost, "/api/ledger/import", map[string]any{"csv": csv2}, nil)

	w := doReq(t, h, http.MethodGet, "/api/ledger/diff", nil, nil)
	var res struct {
		Summary struct {
			LedgerTotal int `json:"ledger_total"`
			HostTotal   int `json:"host_total"`
			Managed     int `json:"managed"`
			Unmanaged   int `json:"unmanaged"`
			Ghost       int `json:"ghost"`
			IPMismatch  int `json:"ip_mismatch"`
		} `json:"summary"`
		Managed    []map[string]any `json:"managed"`
		Unmanaged  []map[string]any `json:"unmanaged"`
		Ghost      []map[string]any `json:"ghost"`
		IPMismatch []map[string]any `json:"ip_mismatch"`
	}
	mustJSON(t, w, &res)

	if res.Summary.LedgerTotal != 3 || res.Summary.HostTotal != 3 {
		t.Fatalf("汇总基数不对: %+v", res.Summary)
	}
	if res.Summary.Managed != 1 || len(res.Managed) != 1 {
		t.Fatalf("在册在网=%d 期望 1", res.Summary.Managed)
	}
	if got := res.Managed[0]["department"]; got != "办公室" {
		t.Fatalf("在册条目应带出台账归属单位，实际=%v", got)
	}
	if res.Summary.Unmanaged != 1 || res.Unmanaged[0]["ip"] != "10.0.0.77" {
		t.Fatalf("台账外设备不对: %+v", res.Unmanaged)
	}
	if res.Summary.Ghost != 1 || res.Ghost[0]["ip"] != "10.0.0.99" {
		t.Fatalf("台账僵尸不对: %+v", res.Ghost)
	}
	if res.Summary.IPMismatch != 1 || res.IPMismatch[0]["ledger_ip"] != "10.0.0.13" {
		t.Fatalf("同机换 IP 不对: %+v", res.IPMismatch)
	}
}

func TestLedgerClear(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	doReq(t, h, http.MethodPost, "/api/ledger/import",
		map[string]any{"csv": "ip\n10.0.0.11\n"}, nil)

	w := doReq(t, h, http.MethodDelete, "/api/ledger", nil, nil)
	var del struct{ Deleted int }
	mustJSON(t, w, &del)
	if del.Deleted != 1 {
		t.Fatalf("清空条数=%d 期望 1", del.Deleted)
	}
	lw := doReq(t, h, http.MethodGet, "/api/ledger", nil, nil)
	var list struct{ Total int }
	mustJSON(t, lw, &list)
	if list.Total != 0 {
		t.Fatalf("清空后仍有 %d 条", list.Total)
	}
}

func TestLedgerImportRejectsBadCSV(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, http.MethodPost, "/api/ledger/import",
		map[string]any{"csv": "名称,备注\nfoo,bar\n"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺少 IP 列应返回 400，实际=%d body=%s", w.Code, w.Body.String())
	}
}
