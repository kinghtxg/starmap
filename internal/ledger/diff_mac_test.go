package ledger

// 账实对照的 MAC 校验回归测试（V1.5.2 新增）。
//
// 背景：V1.5.1 的 Diff 只要 IP 命中就判「在册在网」，完全不看 MAC；
// 并且 item() 用台账 MAC 覆盖观测 MAC。二者叠加的后果是：
// 一台 MAC 完全不同的新设备占用了已登记 IP 时，报告上显示的是
// "台账里那台机器在册在网"，真实设备的 MAC 被一行人工登记抹掉。
// 这个产品最核心的产出是「台账外设备」，而上面这个行为恰好把账外设备
// 静默洗白成在册设备 —— 是假阴性，比误报危险得多。

import (
	"testing"

	"starmap/internal/model"
)

// entry 构造一条台账记录。
func entry(ip, mac, hostname, dept, owner string) model.LedgerEntry {
	return model.LedgerEntry{IP: ip, MAC: mac, Hostname: hostname, Department: dept, Owner: owner}
}

// host 构造一台观测到的主机。
func host(nodeKey, mac string, ips ...string) Host {
	return Host{NodeKey: nodeKey, MAC: mac, IPs: ips, Online: true}
}

// TestDiffIPReusedByDifferentDevice 是本轮最关键的用例：
// 已登记 IP 被另一台设备占用时，必须报成「账外 + 僵尸」，不能报「在册在网」。
func TestDiffIPReusedByDifferentDevice(t *testing.T) {
	entries := []model.LedgerEntry{
		entry("192.168.1.10", "aa:aa:aa:aa:aa:01", "caizhang-pc", "财务部", "老张"),
	}
	hosts := []Host{
		host("mac:bb:bb:bb:bb:bb:02", "bb:bb:bb:bb:bb:02", "192.168.1.10"),
	}

	r := Diff(entries, hosts)

	if r.Summary.Managed != 0 {
		t.Fatalf("IP 被另一台设备占用，却仍判为「在册在网」%d 条：%+v", r.Summary.Managed, r.Managed)
	}
	if r.Summary.Unmanaged != 1 {
		t.Fatalf("占用该 IP 的新设备应判「台账外」，实际 unmanaged=%d", r.Summary.Unmanaged)
	}
	if r.Summary.Ghost != 1 {
		t.Fatalf("台账登记的那台设备已不在网，应判「僵尸」，实际 ghost=%d", r.Summary.Ghost)
	}

	// 观测 MAC 不许被台账 MAC 覆盖
	um := r.Unmanaged[0]
	if um.MAC != "bb:bb:bb:bb:bb:02" {
		t.Fatalf("账外设备应保留**观测** MAC bb:bb:bb:bb:bb:02，实际 %q", um.MAC)
	}
	if um.NodeKey != "mac:bb:bb:bb:bb:bb:02" {
		t.Fatalf("node_key 错乱：%q", um.NodeKey)
	}

	gh := r.Ghost[0]
	if gh.MAC != "aa:aa:aa:aa:aa:01" || gh.Owner != "老张" {
		t.Fatalf("僵尸条目应保留台账信息，实际 mac=%q owner=%q", gh.MAC, gh.Owner)
	}
}

// TestDiffManagedKeepsObservedMAC 正常在册设备：MAC 一致时两列都要给出，且标记 matched。
func TestDiffManagedKeepsObservedMAC(t *testing.T) {
	entries := []model.LedgerEntry{
		entry("10.0.0.11", "AA-BB-CC-00-00-11", "oa-pc-01", "办公室", "张三"),
	}
	// 台账写短横线、观测是冒号小写 —— 必须视为同一台
	hosts := []Host{
		host("mac:aa:bb:cc:00:00:11", "aa:bb:cc:00:00:11", "10.0.0.11"),
	}

	r := Diff(entries, hosts)
	if r.Summary.Managed != 1 || r.Summary.Unmanaged != 0 {
		t.Fatalf("MAC 一致（仅大小写/分隔符不同）应判在册，实际 managed=%d unmanaged=%d",
			r.Summary.Managed, r.Summary.Unmanaged)
	}
	it := r.Managed[0]
	if it.MAC != "aa:bb:cc:00:00:11" {
		t.Fatalf("观测 MAC 被改写：%q", it.MAC)
	}
	if it.LedgerMAC != "AA-BB-CC-00-00-11" {
		t.Fatalf("台账 MAC 应原样保留在 ledger_mac：%q", it.LedgerMAC)
	}
	if it.MACMatched != "yes" {
		t.Fatalf("MACMatched 应为 yes，实际 %q", it.MACMatched)
	}
}

// TestDiffNoMACDoesNotAccuse 缺证据不能当证据用。
// 台账没登记 MAC（很常见）时，同一 IP 上出现设备必须仍判在册——
// 否则一导入不带 MAC 的台账，全网设备会立刻变成"账外"。
func TestDiffNoMACDoesNotAccuse(t *testing.T) {
	cases := []struct {
		name  string
		entry model.LedgerEntry
		host  Host
	}{
		{"台账无MAC", entry("10.0.0.12", "", "oa-pc-02", "", ""), host("mac:cc:cc:cc:cc:cc:03", "cc:cc:cc:cc:cc:03", "10.0.0.12")},
		{"观测无MAC", entry("10.0.0.12", "cc:cc:cc:cc:cc:03", "oa-pc-02", "", ""), host("ip:10.0.0.12", "", "10.0.0.12")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Diff([]model.LedgerEntry{c.entry}, []Host{c.host})
			if r.Summary.Managed != 1 {
				t.Fatalf("缺 MAC 时应判在册（无法证伪），实际 managed=%d unmanaged=%d ghost=%d",
					r.Summary.Managed, r.Summary.Unmanaged, r.Summary.Ghost)
			}
			if r.Managed[0].MACMatched != "unknown" {
				t.Fatalf("MACMatched 应为 unknown，实际 %q", r.Managed[0].MACMatched)
			}
		})
	}
}

// TestDiffMultiIPHost 多网卡主机：某个 IP 被占用不代表整台设备不在册，
// 其它 IP 命中就应按那个 IP 记账。
func TestDiffMultiIPHost(t *testing.T) {
	entries := []model.LedgerEntry{
		entry("10.0.0.20", "aa:aa:aa:aa:00:20", "dual-nic", "信息中心", "李工"),
	}
	hosts := []Host{
		host("mac:aa:aa:aa:aa:00:20", "aa:aa:aa:aa:00:20", "10.0.0.99", "10.0.0.20"),
	}
	r := Diff(entries, hosts)
	if r.Summary.Managed != 1 {
		t.Fatalf("多 IP 主机应有一项命中台账，实际 managed=%d unmanaged=%d", r.Summary.Managed, r.Summary.Unmanaged)
	}
	if r.Managed[0].IP != "10.0.0.99" {
		// primaryIP 取 h.IPs[0]：展示第一个地址，但命中用的是台账登记的那个
		t.Logf("展示 IP=%q（台账 IP=%q）", r.Managed[0].IP, r.Managed[0].LedgerIP)
	}
}

// TestDiffSameDeviceNewIP 同机换 IP：MAC 对得上、IP 不符 → 信息不符。
func TestDiffSameDeviceNewIP(t *testing.T) {
	entries := []model.LedgerEntry{
		entry("10.0.0.30", "aa:aa:aa:aa:00:30", "moved-pc", "办公室", "王五"),
	}
	hosts := []Host{
		host("mac:aa:aa:aa:aa:00:30", "aa:aa:aa:aa:00:30", "10.0.0.31"),
	}
	r := Diff(entries, hosts)
	if r.Summary.IPMismatch != 1 {
		t.Fatalf("同机换 IP 应判「信息不符」，实际 %+v", r.Summary)
	}
	if r.Summary.Ghost != 0 {
		t.Fatalf("同机换 IP 不应同时报僵尸，实际 ghost=%d", r.Summary.Ghost)
	}
	if r.IPMismatch[0].MACMatched != "yes" {
		t.Fatalf("MACMatched 应为 yes，实际 %q", r.IPMismatch[0].MACMatched)
	}
}

// TestDiffTwoDevicesSwapIPs 两台设备互换 IP（DHCP 重排后很常见）：
// 两台都必须按 MAC 认出自己那条台账，不能互相顶替。
func TestDiffTwoDevicesSwapIPs(t *testing.T) {
	entries := []model.LedgerEntry{
		entry("10.0.0.40", "aa:aa:aa:aa:00:40", "pc-a", "A", "甲"),
		entry("10.0.0.41", "aa:aa:aa:aa:00:41", "pc-b", "B", "乙"),
	}
	hosts := []Host{
		host("mac:aa:aa:aa:aa:00:40", "aa:aa:aa:aa:00:40", "10.0.0.41"), // A 现在在 B 的旧地址上
		host("mac:aa:aa:aa:aa:00:41", "aa:aa:aa:aa:00:41", "10.0.0.40"), // B 在 A 的旧地址上
	}
	r := Diff(entries, hosts)

	if r.Summary.IPMismatch != 2 {
		t.Fatalf("互换 IP 的两台设备都应判「信息不符」，实际 %+v", r.Summary)
	}
	if r.Summary.Managed != 0 || r.Summary.Ghost != 0 || r.Summary.Unmanaged != 0 {
		t.Fatalf("不应产生在册/僵尸/账外，实际 %+v", r.Summary)
	}
	for _, it := range r.IPMismatch {
		if it.MAC != it.LedgerMAC || it.MACMatched != "yes" {
			t.Fatalf("应按 MAC 认回自己的台账：mac=%q ledger_mac=%q matched=%q",
				it.MAC, it.LedgerMAC, it.MACMatched)
		}
	}
}
