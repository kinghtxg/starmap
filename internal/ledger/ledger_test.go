package ledger

import (
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

const sampleCSV = "\ufeffIP地址, MAC地址, 主机名, 操作系统, 归属单位, 归属人, 物理位置, 备注\n" +
	"10.0.0.11, AA-BB-CC-00-00-11, oa-pc-01, Windows 10, 办公室, 张三, 3F-301, 正常办公\n" +
	"10.0.0.12, aa:bb:cc:00:00:12, oa-pc-02, Windows 10, 办公室, 李四, 3F-302,\n" +
	"192.168.9.9, , legacy-srv, CentOS 7, 机房, 王五, B1-机房, 已报废待下架\n" +
	"not-an-ip, , bad, , , , , 非法行\n" +
	"\n" +
	"10.0.0.11, , dup, , , , , 重复行\n"

func TestParseCSVHeaderTolerance(t *testing.T) {
	entries, st, err := ParseCSV(strings.NewReader(sampleCSV), "台账.xlsx.csv")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("有效条目=%d 期望 3（非法 IP 与重复 IP 应跳过）", len(entries))
	}
	if st.Valid != 3 || st.Skipped != 2 {
		t.Fatalf("统计不对: %+v", st)
	}
	first := entries[0]
	if first.IP != "10.0.0.11" || first.MAC != "aa:bb:cc:00:00:11" {
		t.Fatalf("BOM/表头别名/MAC 归一化失败: %+v", first)
	}
	if first.Department != "办公室" || first.Owner != "张三" || first.Location != "3F-301" {
		t.Fatalf("中文字段映射失败: %+v", first)
	}
	if first.Batch != "台账.xlsx.csv" {
		t.Fatalf("批次未记录: %+v", first)
	}
}

func TestParseCSVEnglishHeaders(t *testing.T) {
	csv := "ip,mac,hostname,os,department,owner,location,note\n10.1.1.1,00:11:22:33:44:55,wks01,Ubuntu,IT,alice,2F,ok\n"
	entries, _, err := ParseCSV(strings.NewReader(csv), "en.csv")
	if err != nil {
		t.Fatalf("英文表头解析失败: %v", err)
	}
	if len(entries) != 1 || entries[0].Department != "IT" || entries[0].Description != "ok" {
		t.Fatalf("英文字段映射失败: %+v", entries)
	}
}

func TestParseCSVNoIPColumn(t *testing.T) {
	_, _, err := ParseCSV(strings.NewReader("名称,备注\nfoo,bar\n"), "x.csv")
	if err == nil {
		t.Fatal("缺少 IP 列时应当报错")
	}
}

func TestDiffFourKinds(t *testing.T) {
	now := time.Now().UTC()
	entries := []model.LedgerEntry{
		{IP: "10.0.0.11", MAC: "aa:bb:cc:00:00:11", Department: "办公室", Owner: "张三"},
		{IP: "10.0.0.12", MAC: "aa:bb:cc:00:00:12"},
		{IP: "10.0.0.13", MAC: "aa:bb:cc:00:00:99"}, // 同机换 IP：台账 .13，实际 .31
		{IP: "10.0.0.99", MAC: "aa:bb:cc:00:00:99"}, // 僵尸：网内从未出现
		{IP: "10.0.0.88"}, // 僵尸
	}
	hosts := []Host{
		{NodeKey: "mac:aa:bb:cc:00:00:11", IPs: []string{"10.0.0.11"}, MAC: "aa:bb:cc:00:00:11", Online: true, LastSeen: now},
		{NodeKey: "mac:aa:bb:cc:00:00:12", IPs: []string{"10.0.0.12"}, MAC: "aa:bb:cc:00:00:12", Online: true},
		// MAC 对得上台账 .13，但实际 IP 是 .31
		{NodeKey: "mac:aa:bb:cc:00:00:99", IPs: []string{"10.0.0.31"}, MAC: "aa:bb:cc:00:00:99", Online: true, RiskLevel: model.RiskHigh},
		// 台账里没有的影子设备
		{NodeKey: "mac:aa:bb:cc:00:00:77", IPs: []string{"10.0.0.77"}, MAC: "aa:bb:cc:00:00:77", Online: true, RiskLevel: model.RiskMid},
	}

	res := Diff(entries, hosts)

	if len(res.Managed) != 2 {
		t.Fatalf("在册在网=%d 期望 2: %+v", len(res.Managed), res.Managed)
	}
	if len(res.IPMismatch) != 1 {
		t.Fatalf("IP 不符=%d 期望 1: %+v", len(res.IPMismatch), res.IPMismatch)
	}
	mi := res.IPMismatch[0]
	if mi.IP != "10.0.0.31" || mi.LedgerIP != "10.0.0.13" {
		t.Fatalf("IP 不符条目应同时带观测 IP 与台账 IP: %+v", mi)
	}
	if len(res.Unmanaged) != 1 || res.Unmanaged[0].IP != "10.0.0.77" {
		t.Fatalf("台账外设备不对: %+v", res.Unmanaged)
	}
	if len(res.Ghost) != 2 {
		t.Fatalf("台账僵尸=%d 期望 2: %+v", len(res.Ghost), res.Ghost)
	}
	if res.Summary.LedgerTotal != 5 || res.Summary.HostTotal != 4 {
		t.Fatalf("汇总不对: %+v", res.Summary)
	}
	// 台账信息优先（人工登记更权威）
	if res.Managed[0].Department == "" {
		t.Fatal("在册条目应带出台账里的归属单位")
	}
}

func TestDiffUnmanagedSortedByRisk(t *testing.T) {
	hosts := []Host{
		{NodeKey: "a", IPs: []string{"10.0.0.9"}, RiskLevel: model.RiskNone},
		{NodeKey: "b", IPs: []string{"10.0.0.10"}, RiskLevel: model.RiskHigh},
		{NodeKey: "c", IPs: []string{"10.0.0.2"}, RiskLevel: model.RiskNone},
	}
	res := Diff(nil, hosts)
	if len(res.Unmanaged) != 3 {
		t.Fatalf("台账为空时全部应为台账外: %+v", res.Unmanaged)
	}
	if res.Unmanaged[0].IP != "10.0.0.10" {
		t.Fatalf("高风险设备应排最前，实际首位=%s", res.Unmanaged[0].IP)
	}
	// 其余按 IP 数值排序：.2 在 .9 之前
	if res.Unmanaged[1].IP != "10.0.0.2" || res.Unmanaged[2].IP != "10.0.0.9" {
		t.Fatalf("IP 应按数值排序，实际=%v,%v", res.Unmanaged[1].IP, res.Unmanaged[2].IP)
	}
}

func TestDiffEmptyLedger(t *testing.T) {
	res := Diff(nil, nil)
	if res.Summary.LedgerTotal != 0 || res.Summary.Unmanaged != 0 {
		t.Fatalf("空对照结果应为全零: %+v", res.Summary)
	}
	if res.Managed == nil || res.Unmanaged == nil || res.Ghost == nil || res.IPMismatch == nil {
		t.Fatal("四类结果应返回空数组而非 nil（JSON 序列化后才是 [] 而不是 null）")
	}
}
