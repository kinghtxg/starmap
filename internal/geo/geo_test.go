package geo

import "testing"

// 这份数据是"红色告警"的地基：错一个段，就会把国内地址标成国外。
// 因此用例覆盖三类：典型国内、典型国外、不该判定归属的地址。
func TestIsOverseasKnownChinese(t *testing.T) {
	for _, ip := range []string{"114.114.114.114", "223.5.5.5", "180.101.49.11", "119.29.29.29", "1.2.4.8"} {
		overseas, known := IsOverseas(ip)
		if !known {
			t.Errorf("%s 应有归属判定", ip)
			continue
		}
		if overseas {
			t.Errorf("%s 是国内地址，不应判为国外", ip)
		}
	}
}

func TestIsOverseasKnownForeign(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.217.163.36", "104.244.42.1"} {
		overseas, known := IsOverseas(ip)
		if !known {
			t.Errorf("%s 应有归属判定", ip)
			continue
		}
		if !overseas {
			t.Errorf("%s 是国外地址，应判为国外", ip)
		}
	}
}

// 内网/回环/组播不是"国外/国内"的问题：必须返回 known=false，
// 否则拓扑里每个内网节点都会被当成国外标红。
func TestIsOverseasNotApplicable(t *testing.T) {
	for _, ip := range []string{
		"192.168.31.1", "10.0.0.1", "172.16.0.1", "127.0.0.1",
		"169.254.1.1", "224.0.0.251", "239.255.255.250", "0.0.0.0",
		"100.64.0.1", "255.255.255.255",
		"fe80::1", "2400:3200::1", "", "not-an-ip", "1.2.3",
	} {
		overseas, known := IsOverseas(ip)
		if known {
			t.Errorf("%q 不应给出归属结论（overseas=%v）", ip, overseas)
		}
	}
}

// 外部聚合节点存的是 "/24" 形式，必须能判定。
func TestIsOverseasCIDRSuffix(t *testing.T) {
	if overseas, known := IsOverseas("8.8.8.0/24"); !known || !overseas {
		t.Fatalf("8.8.8.0/24 应判为国外（known=%v overseas=%v）", known, overseas)
	}
	if overseas, known := IsOverseas("114.114.114.0/24"); !known || overseas {
		t.Fatalf("114.114.114.0/24 不应判为国外（known=%v overseas=%v）", known, overseas)
	}
}

// 数据完整性：段数太少或最大段偏小，说明嵌入的数据被截断了。
func TestDataCoverage(t *testing.T) {
	st := Info()
	if st.LoadErr != "" {
		t.Fatalf("数据加载失败：%s", st.LoadErr)
	}
	if st.Ranges < 1000 {
		t.Fatalf("区间数 %d 明显偏少，数据可能被截断", st.Ranges)
	}
	if st.TopRange < "200.0.0.0" && len(st.TopRange) >= 3 && st.TopRange[0] == '1' {
		t.Fatalf("最大段 %s 偏小，数据可能被截断", st.TopRange)
	}
	if _, known := IsOverseas("223.255.253.1"); !known {
		t.Fatal("223.255.253.1 应能判定")
	}
}

func TestParseIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"1.2.3.4", 0x01020304, true},
		{"1.2.3.0/24", 0x01020300, true},
		{"255.255.255.255", 0xFFFFFFFF, true},
		{"1.2.3", 0, false},
		{"1.2.3.4.5", 0, false},
		{"1.2.3.256", 0, false},
		{"::1", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := parseIPv4(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseIPv4(%q) = (%#x, %v), want (%#x, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
