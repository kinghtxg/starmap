package ledger

import (
	"bytes"
	"testing"

	"starmap/internal/model"
)

// ParseCSV 直接吃用户上传的文件（可能是 Excel 导出的、编码混乱的、被截断的）。
// 它必须要么返回 ok=false 的条目，要么返回 error，绝不能 panic。
//
// 常规验证：go test ./internal/ledger/
// 深度模糊：go test ./internal/ledger/ -fuzz=FuzzParseCSV -fuzztime=60s
func FuzzParseCSV(f *testing.F) {
	seeds := []string{
		"ip,mac,hostname\n10.0.0.1,aa:bb:cc:dd:ee:ff,pc1\n",
		"IP地址,MAC地址,主机名,部门\n10.0.0.2,AA-BB-CC-DD-EE-FF,pc2,财务\n",
		"",
		"ip\n",
		"\xef\xbb\xbfip,mac\n10.0.0.3,\n", // 带 BOM
		"ip,mac\n10.0.0.4,not-a-mac\n",
		"ip,mac\n999.999.999.999,aa:bb\n",
		"ip,mac,os,owner,location,description\n10.0.0.5,aa:bb:cc:dd:ee:01,Windows,张三,3F,备注\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, stats, err := ParseCSV(bytes.NewReader(data), "fuzz")
		// error 与 entries 互斥语义：出错时不应再返回条目
		if err != nil && len(entries) > 0 {
			t.Fatalf("返回 error 时不应同时产出条目（%d 条）: %v", len(entries), err)
		}
		// 统计口径自洽：有效 + 跳过 = 数据行数
		if stats.Rows < 0 || stats.Valid < 0 || stats.Skipped < 0 {
			t.Fatalf("统计出现负数: %+v", stats)
		}
		if stats.Valid+stats.Skipped != stats.Rows {
			t.Fatalf("有效(%d)+跳过(%d) 应等于行数(%d)", stats.Valid, stats.Skipped, stats.Rows)
		}
		if len(entries) != stats.Valid {
			t.Fatalf("条目数(%d) 应等于有效率(%d)", len(entries), stats.Valid)
		}
		// 解析出的每条都要有可用 IP（没有 IP 的台账行无对照意义）
		for _, e := range entries {
			if e.IP == "" {
				t.Fatal("产出了无 IP 的台账条目")
			}
		}
	})
}

// FuzzDiff 台账对照吃的是两方数据（台账 + 观测），同样不能 panic。
func FuzzDiff(f *testing.F) {
	f.Add("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.1", "aa:bb:cc:dd:ee:ff")
	f.Add("", "", "", "")
	f.Add("10.0.0.2", "", "10.0.0.2", "11:22:33:44:55:66")
	f.Fuzz(func(t *testing.T, lip, lmac, hip, hmac string) {
		var entries []model.LedgerEntry
		if lip != "" {
			entries = append(entries, model.LedgerEntry{IP: lip, MAC: lmac})
		}
		var hosts []Host
		if hip != "" {
			hosts = append(hosts, Host{IPs: []string{hip}, MAC: hmac})
		}
		res := Diff(entries, hosts)
		s := res.Summary
		// 汇总与明细必须一致
		if s.Managed != len(res.Managed) || s.Unmanaged != len(res.Unmanaged) ||
			s.Ghost != len(res.Ghost) || s.IPMismatch != len(res.IPMismatch) {
			t.Fatalf("汇总与明细不一致: summary=%+v managed=%d unmanaged=%d ghost=%d mismatch=%d",
				s, len(res.Managed), len(res.Unmanaged), len(res.Ghost), len(res.IPMismatch))
		}
		// 台账条目数守恒：在册 + 僵尸 + IP不符 = 台账总数
		if s.Managed+s.Ghost+s.IPMismatch != s.LedgerTotal {
			t.Fatalf("台账侧不守恒: managed(%d)+ghost(%d)+mismatch(%d) != ledger_total(%d)",
				s.Managed, s.Ghost, s.IPMismatch, s.LedgerTotal)
		}
	})
}
