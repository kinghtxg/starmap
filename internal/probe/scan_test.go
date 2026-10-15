package probe

import (
	"errors"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/topology"
)

func newTestScanner() (*Scanner, *topology.Engine) {
	eng := topology.New(model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
	})
	s := New(eng)
	s.NowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	return s, eng
}

// setGOOS 临时切换平台并返回恢复函数（串行测试用）。
func setGOOS(g string) func() {
	orig := goos
	goos = g
	return func() { goos = orig }
}

func TestTriggerDisabled(t *testing.T) {
	s, _ := newTestScanner()
	if _, err := s.Trigger("icmp", "192.168.1.1"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("默认关闭应返回 ErrDisabled，实际 %v", err)
	}
}

func TestTriggerInvalidType(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	if _, err := s.Trigger("syn_scan", "192.168.1.1"); err == nil {
		t.Fatal("非法类型应报错")
	}
}

func TestTriggerICMPInject(t *testing.T) {
	s, eng := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(string) (string, error) { return "/bin/ping", nil }
	s.run = func(name string, args ...string) (string, error) {
		return "3 packets transmitted, 3 received\n64 bytes from 192.168.1.1: ttl=64", nil
	}
	res, err := s.Trigger("icmp", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("应有 1 存活主机: %+v", res)
	}
	if n := eng.NodeByIP("192.168.1.1"); n == nil || !n.Active {
		t.Fatal("探测结果应注入拓扑引擎")
	}
}

func TestTriggerICMPUnreachable(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(string) (string, error) { return "/bin/ping", nil }
	s.run = func(name string, args ...string) (string, error) { return "", errors.New("exit 1") }
	res, err := s.Trigger("icmp", "192.168.1.99")
	if err == nil {
		t.Fatal("不可达应返回错误")
	}
	if res == nil || len(res.Hosts) != 0 {
		t.Fatal("不可达不应有主机")
	}
}

func TestICMPPingCIDR(t *testing.T) {
	// 修复：ICMP 探测支持 CIDR 网段（此前 /24 报"无法解析"）
	s, _ := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(string) (string, error) { return "/bin/ping", nil }
	s.run = func(name string, args ...string) (string, error) {
		// 最后一个参数是目标 IP
		ip := args[len(args)-1]
		if ip == "192.168.1.1" || ip == "192.168.1.2" {
			return "64 bytes from " + ip + ": ttl=64", nil
		}
		return "Request timed out.", nil
	}
	res, err := s.Trigger("icmp", "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("网段扫描应发现 2 台存活主机，实际 %d: %+v", len(res.Hosts), res.Hosts)
	}
}

func TestTriggerNoPingGraceful(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(string) (string, error) { return "", errors.New("not found") }
	if _, err := s.Trigger("icmp", "192.168.1.1"); err == nil {
		t.Fatal("无 ping 命令应报错")
	}
	if _, err := s.Trigger("traceroute", "8.8.8.8"); err == nil {
		t.Fatal("无 traceroute/tracert 应报错")
	}
}

// ---------- expandTarget（P1-3 修复回归） ----------

func TestExpandTargetSingle(t *testing.T) {
	ips, err := expandTarget("192.168.1.5", 254)
	if err != nil || len(ips) != 1 || ips[0] != "192.168.1.5" {
		t.Fatalf("单 IP 应原样返回: %v %v", ips, err)
	}
}

func TestExpandTarget30(t *testing.T) {
	ips, err := expandTarget("192.168.1.0/30", 254)
	if err != nil || len(ips) != 2 {
		t.Fatalf("/30 应展开 2 个主机地址（去网络+广播），实际 %v err=%v", ips, err)
	}
	if ips[0] != "192.168.1.1" || ips[1] != "192.168.1.2" {
		t.Fatalf("/30 展开错误: %v", ips)
	}
}

func TestExpandTarget24(t *testing.T) {
	// P1-3 核心回归：/24 = 254 个主机，之前被误判为「过大」
	ips, err := expandTarget("192.168.31.0/24", 254)
	if err != nil {
		t.Fatalf("/24 不应报过大: %v", err)
	}
	if len(ips) != 254 {
		t.Fatalf("/24 应展开 254 个主机地址，实际 %d", len(ips))
	}
	if ips[0] != "192.168.31.1" {
		t.Fatalf("首地址应为 .1，实际 %s", ips[0])
	}
	if ips[len(ips)-1] != "192.168.31.254" {
		t.Fatalf("末地址应为 .254（不含广播 .255），实际 %s", ips[len(ips)-1])
	}
}

func TestExpandTarget31(t *testing.T) {
	// /31 点对点，两个地址都可用，无网络/广播
	ips, err := expandTarget("10.0.0.0/31", 254)
	if err != nil || len(ips) != 2 {
		t.Fatalf("/31 应展开 2 个地址: %v err=%v", ips, err)
	}
	if ips[0] != "10.0.0.0" || ips[1] != "10.0.0.1" {
		t.Fatalf("/31 展开错误: %v", ips)
	}
}

func TestExpandTargetLarge(t *testing.T) {
	if _, err := expandTarget("10.0.0.0/8", 254); err == nil {
		t.Fatal("超大网段应拒绝")
	}
	if _, err := expandTarget("10.0.0.0/16", 254); err == nil {
		t.Fatal("/16 应拒绝")
	}
}

func TestExpandTargetInvalid(t *testing.T) {
	if _, err := expandTarget("not-an-ip", 254); err == nil {
		t.Fatal("非法目标应报错")
	}
	if _, err := expandTarget("2001:db8::/64", 254); err == nil {
		t.Fatal("IPv6 网段应拒绝（仅支持单 IP）")
	}
}

// ---------- 平台命令构造 ----------

func TestPingArgs(t *testing.T) {
	reset := setGOOS("linux")
	if a := pingArgs(3, 2); a[0] != "-c" || a[1] != "3" || a[2] != "-W" || a[3] != "2" {
		t.Fatalf("linux pingArgs 错误: %v", a)
	}
	reset()
	reset = setGOOS("windows")
	if a := pingArgs(3, 2); a[0] != "-n" || a[1] != "3" || a[2] != "-w" || a[3] != "2000" {
		t.Fatalf("windows pingArgs 错误: %v", a)
	}
	reset()
}

func TestIsPingAlive(t *testing.T) {
	cases := map[string]bool{
		"64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.2 ms": true,  // linux
		"Reply from 192.168.1.1: bytes=32 time<1ms TTL=64":         true,  // windows en
		"来自 192.168.1.1 的回复: 字节=32 时间<1ms TTL=64":                true,  // windows zh
		"请求超时。":                                                        false, // windows zh timeout
		"Request timed out.":                                          false, // windows en timeout
		"100% packet loss":                                            false,
	}
	for out, want := range cases {
		if got := isPingAlive(out); got != want {
			t.Fatalf("isPingAlive(%q)=%v 期望 %v", out, got, want)
		}
	}
}

func TestIsMACWindows(t *testing.T) {
	if !isMACWindows("00-11-22-33-44-55") {
		t.Fatal("合法 Windows MAC 应识别")
	}
	if isMACWindows("00:11:22:33:44:55") {
		t.Fatal("冒号分隔不应识别为 Windows MAC")
	}
	if isMACWindows("gg-11-22-33-44-55") {
		t.Fatal("非法十六进制应拒绝")
	}
	if isMACWindows("00-11-22-33-44") {
		t.Fatal("长度不足应拒绝")
	}
}

func TestNormalizeMAC(t *testing.T) {
	if got := normalizeMAC("00-11-22-33-44-55"); got != "00:11:22:33:44:55" {
		t.Fatalf("归一化错误: %s", got)
	}
}

// ---------- Windows ARP 表解析 ----------

func TestReadARPTableWindows(t *testing.T) {
	s, _ := newTestScanner()
	s.run = func(name string, args ...string) (string, error) {
		if name == "arp" {
			return "接口: 192.168.31.1 --- 0x3\n" +
				"  Internet 地址          物理地址              类型\n" +
				"  192.168.31.100          00-11-22-33-44-55     动态\n" +
				"  192.168.31.101          aa-bb-cc-dd-ee-ff     动态\n" +
				"  192.168.31.255          ff-ff-ff-ff-ff-ff     静态\n", nil
		}
		return "", nil
	}
	table := s.readARPTableWindows()
	if len(table) != 2 {
		t.Fatalf("应解析 2 条动态条目，实际 %v", table)
	}
	if table["192.168.31.100"] != "00:11:22:33:44:55" {
		t.Fatalf("MAC 应归一化为冒号分隔: %v", table)
	}
	if table["192.168.31.101"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC 归一化错误: %v", table)
	}
}

// ---------- ARP 扫描端到端（Windows 分支） ----------

func TestARPscanWindows(t *testing.T) {
	defer setGOOS("windows")()
	s, eng := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(name string) (string, error) {
		if name == "ping" {
			return "C:\\Windows\\System32\\PING.EXE", nil
		}
		return "", errors.New("not found")
	}
	s.run = func(name string, args ...string) (string, error) {
		if name == "arp" {
			return "接口: 192.168.31.1 --- 0x3\n" +
				"  192.168.31.20          00-aa-00-aa-00-aa     动态\n", nil
		}
		return "", nil // ping
	}
	res, err := s.Trigger("arp", "192.168.31.0/24")
	if err != nil {
		t.Fatalf("ARP 扫描失败: %v", err)
	}
	if len(res.Hosts) != 1 || res.Hosts[0].IP != "192.168.31.20" {
		t.Fatalf("应发现 192.168.31.20，实际 %+v", res.Hosts)
	}
	if res.Hosts[0].MAC != "00:aa:00:aa:00:aa" {
		t.Fatalf("MAC 应归一化: %+v", res.Hosts[0])
	}
	// 结果注入拓扑
	if n := eng.NodeByIP("192.168.31.20"); n == nil {
		t.Fatal("ARP 发现主机应注入拓扑")
	}
}

// ---------- traceroute 解析 ----------

func TestParseTraceroute(t *testing.T) {
	out := "traceroute to 8.8.8.8\n 1  192.168.1.1  1 ms\n 2  * * *\n 3  100.64.0.1  5 ms\n"
	hits := parseTraceroute(out)
	if len(hits) != 2 || hits[0].IP != "192.168.1.1" || hits[1].Hop != 3 {
		t.Fatalf("解析错误: %+v", hits)
	}
}

func TestParseTracertWindows(t *testing.T) {
	out := "通过最多 30 个跃点跟踪到 8.8.8.8 的路由\n" +
		"  1     1 ms     1 ms     1 ms  192.168.31.1\n" +
		"  2     2 ms     1 ms     1 ms  100.64.0.1\n" +
		"  3     *        *        *     请求超时。\n"
	hits := parseTracertWindows(out)
	if len(hits) != 2 || hits[0].IP != "192.168.31.1" || hits[0].Hop != 1 {
		t.Fatalf("Windows tracert 解析错误: %+v", hits)
	}
	if hits[1].IP != "100.64.0.1" || hits[1].Hop != 2 {
		t.Fatalf("第二跳解析错误: %+v", hits[1])
	}
}
