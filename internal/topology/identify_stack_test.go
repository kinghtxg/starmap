package topology

import (
	"path/filepath"
	"testing"

	"starmap/internal/model"
	"starmap/internal/store"
)

// openTestStore 打开一个临时文件库（":memory:" 无法验证跨引擎恢复）。
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "identify.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// 系统栈 / 软件识别（V1.5 深化）测试。
//
// 这一层的价值判断标准：能不能把"一台开着 80 端口的机器"说成
// "跑 nginx 的 Windows 10 桌面"——而且说错方向（把服务端软件记到客户端头上）
// 比不说更糟，因为它看起来像是证据。

const winChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36"

func mkHTTP(srcIP, dstIP, mac string, srcPort, dstPort uint16, ua, srv string, ttl int) *model.Session {
	s := mkSvc(srcIP, dstIP, mac, srcPort, dstPort, base)
	s.UserAgent = ua
	s.HTTPServer = srv
	s.StartTTL = ttl
	return s
}

func hasSoftware(n *model.Node, want string) bool {
	for _, s := range n.Software {
		if s == want {
			return true
		}
	}
	return false
}

// UA 属于客户端、Server 头属于服务端——不能混为一谈。
func TestSoftwareAttributionClientVsServer(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkHTTP("192.168.31.20", "192.168.31.100", "aa:bb:cc:00:00:20",
		50123, 80, winChromeUA, "nginx/1.18.0", 128))

	snap := e.Snapshot()
	client := snapNodeByIP(snap, "192.168.31.20")
	server := snapNodeByIP(snap, "192.168.31.100")
	if client == nil || server == nil {
		t.Fatal("节点缺失")
	}
	if !hasSoftware(client, "Windows 10/11 · Chrome 120") {
		t.Fatalf("客户端应记录 UA 摘要，实际 software=%v", client.Software)
	}
	if hasSoftware(client, "nginx/1.18.0") {
		t.Fatalf("服务端软件不应记到客户端头上，实际 software=%v", client.Software)
	}
	if !hasSoftware(server, "nginx/1.18.0") {
		t.Fatalf("服务端应记录 Server 头，实际 software=%v", server.Software)
	}
	if hasSoftware(server, "Windows 10/11 · Chrome 120") {
		t.Fatalf("客户端 UA 不应记到服务端头上，实际 software=%v", server.Software)
	}
	if client.OSHint != "Windows 10/11" {
		t.Fatalf("客户端系统栈应为 Windows 10/11，实际 %q", client.OSHint)
	}
}

// 方向必须靠端口判定：即便会话的 src 是服务端（服务端先说话/抓包视角不同），
// 也不能把 UA 记到服务端、Server 头记到客户端。
func TestSoftwareAttributionReversedSession(t *testing.T) {
	e := New(testCfg())
	// 源是 192.168.31.100:80（服务端口），目的 192.168.31.20:50124（临时端口）
	e.Ingest(mkHTTP("192.168.31.100", "192.168.31.20", "aa:bb:cc:00:00:64",
		80, 50124, winChromeUA, "nginx/1.18.0", 64))

	snap := e.Snapshot()
	client := snapNodeByIP(snap, "192.168.31.20")
	server := snapNodeByIP(snap, "192.168.31.100")
	if client == nil || server == nil {
		t.Fatal("节点缺失")
	}
	if hasSoftware(client, "nginx/1.18.0") {
		t.Fatalf("方向反了：Server 头被记到客户端，software=%v", client.Software)
	}
	if !hasSoftware(server, "nginx/1.18.0") {
		t.Fatalf("方向反了：服务端应记录 Server 头，software=%v", server.Software)
	}
	if !hasSoftware(client, "Windows 10/11 · Chrome 120") {
		t.Fatalf("客户端应记录 UA 摘要，software=%v", client.Software)
	}
}

// 两端都是服务端口时方向不可判，宁可不记。
func TestSoftwareAttributionAmbiguousPortsSkipped(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkHTTP("192.168.31.30", "192.168.31.40", "aa:bb:cc:00:00:30",
		80, 8080, winChromeUA, "nginx/1.18.0", 64))

	snap := e.Snapshot()
	for _, ip := range []string{"192.168.31.30", "192.168.31.40"} {
		if n := snapNodeByIP(snap, ip); n != nil && len(n.Software) != 0 {
			t.Fatalf("端口不可判方向时不应记软件指纹，%s software=%v", ip, n.Software)
		}
	}
}

// 公网节点不参与软件画像：它背后是成百上千台不同的服务器，
// 把某一台的 nginx 记到聚合节点上，等于给一整段公网地址编造属性。
func TestSoftwareNotRecordedForExternal(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkHTTP("192.168.31.20", "93.184.216.34", "aa:bb:cc:00:00:20",
		50125, 80, winChromeUA, "nginx", 128))

	snap := e.Snapshot()
	found := false
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if !hasLabel(n, LabelExternalAg) {
			continue
		}
		found = true
		if len(n.Software) != 0 {
			t.Fatalf("公网聚合节点不应记软件指纹，实际 %v", n.Software)
		}
	}
	if !found {
		t.Skip("本用例下未生成外部聚合节点")
	}
}

// TTL 取最大值：它是"初始 TTL 减跳数"，取最小会把偶然被多跳衰减的包当指纹。
func TestTTLTakesMax(t *testing.T) {
	e := New(testCfg())
	e.Ingest(mkHTTP("192.168.31.20", "192.168.31.100", "aa:bb:cc:00:00:20", 50126, 80, "", "", 60))
	e.Ingest(mkHTTP("192.168.31.20", "192.168.31.100", "aa:bb:cc:00:00:20", 50127, 80, "", "", 64))

	n := snapNodeByIP(e.Snapshot(), "192.168.31.20")
	if n == nil {
		t.Fatal("节点缺失")
	}
	if n.TTL != 64 {
		t.Fatalf("TTL 应取观测最大值 64，实际 %d", n.TTL)
	}
	if n.OSHint != "类 Unix" {
		t.Fatalf("TTL=64 应推断类 Unix，实际 %q", n.OSHint)
	}
}

func TestOSHintFromTTL(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{0, ""},
		{20, ""}, // 衰减过度，无法区分
		{32, ""},
		{33, "类 Unix"},
		{64, "类 Unix"},
		{65, "Windows"},
		{120, "Windows"},
		{128, "Windows"},
		{129, "网络设备"},
		{254, "网络设备"},
	}
	for _, c := range cases {
		if got := osHintFromTTL(c.ttl); got != c.want {
			t.Errorf("osHintFromTTL(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}

func TestUALabel(t *testing.T) {
	cases := []struct {
		ua   string
		want string
	}{
		{winChromeUA, "Windows 10/11 · Chrome 120"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1", "iOS · Safari 17"},
		{"Mozilla/5.0 (Linux; Android 13; PGT-AN10 Build/HONORPGT-AN10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36 MicroMessenger/8.0.47", "Android · 微信内置浏览器"},
		{"curl/8.4.0", "curl"},
		{"python-requests/2.31.0", "Python 脚本"},
		{"Go-http-client/1.1", "Go 客户端"},
		// Windows 系统组件不带 "Windows NT"，但同样是 Windows 的指纹
		{"Microsoft-CryptoAPI/10.0", "Windows"},
		// 只有"我是浏览器"没有信息量，记下来只是噪声
		{"Mozilla/5.0", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := uaLabel(c.ua); got != c.want {
			t.Errorf("uaLabel(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

// Server 头是对端可控文本，必须清洗并截断后再进内存/界面。
func TestNormalizeServer(t *testing.T) {
	if got := normalizeServer("  nginx/1.18.0\r\n"); got != "nginx/1.18.0" {
		t.Fatalf("应去掉首尾空白与控制字符，实际 %q", got)
	}
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	if got := normalizeServer(string(long)); len([]rune(got)) != maxLabelLen+1 {
		t.Fatalf("超长 Server 头应截断为 %d 字符（含省略号），实际 %d", maxLabelLen+1, len([]rune(got)))
	}
	if got := normalizeServer(""); got != "" {
		t.Fatalf("空串应返回空串，实际 %q", got)
	}
}

// 重启后服务画像要从端口库恢复，而不是一律变"未识别"。
//
// 拓扑节点是持久化的，但端口/对端证据只在内存里滚。不加恢复逻辑，用户每次
// 重启服务都会看到"设备角色全没了"，只会认为识别能力是坏的——而实际证据
// 一直躺在端口库里（source=traffic 的记录就是"有人打到过这个端口"）。
func TestServiceEvidenceRestoredFromPorts(t *testing.T) {
	st := openTestStore(t)
	e1 := New(testCfg())
	if err := e1.AttachStore(st); err != nil {
		t.Fatalf("AttachStore: %v", err)
	}
	// 别人的机器访问它的 5000（群晖 DSM 管理口）
	e1.Ingest(mkSvc("192.168.31.59", "192.168.31.100", "aa:bb:cc:00:00:59", 50070, 5000, base))
	if err := e1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	first := snapNodeByIP(e1.Snapshot(), "192.168.31.100")
	if first == nil {
		t.Fatal("节点缺失")
	}
	key := first.NodeKey
	if key == "" {
		t.Fatal("节点应有 NodeKey")
	}

	// 端口库：一条流量证据 + 一条扫描证据（扫描不算"有人连过"）
	if err := st.UpsertPorts([]model.PortRecord{
		{NodeKey: key, IP: "192.168.31.100", Port: 5000, Proto: "tcp", Source: model.PortSourceTraffic},
		{NodeKey: key, IP: "192.168.31.100", Port: 445, Proto: "tcp", Source: model.PortSourceProbe},
	}); err != nil {
		t.Fatalf("UpsertPorts: %v", err)
	}

	// 模拟重启：新引擎只有库，没有任何内存证据
	e2 := New(testCfg())
	if err := e2.AttachStore(st); err != nil {
		t.Fatalf("AttachStore#2: %v", err)
	}
	n := snapNodeByIP(e2.Snapshot(), "192.168.31.100")
	if n == nil {
		t.Fatal("重启后节点应被恢复")
	}
	if !hasRole(n, RoleNAS) {
		t.Fatalf("重启后应从端口库恢复 NAS 角色，实际 roles=%v ports=%v", n.Roles, n.Ports)
	}
	if !hasPort(n, 5000) {
		t.Fatalf("重启后应恢复端口 5000，实际 %v", n.Ports)
	}
	// nmap 扫出来的 445 只说明"它在听"，不能当成"有人连过"的证据
	if hasPort(n, 445) {
		t.Fatalf("扫描来源的端口不应进服务画像，实际 %v", n.Ports)
	}
}

// 软件标识去重且排序稳定（map 迭代无序会让前端每次刷新都跳）。
func TestSoftwareDedupAndStable(t *testing.T) {
	e := New(testCfg())
	for i := 0; i < 5; i++ {
		e.Ingest(mkHTTP("192.168.31.20", "192.168.31.100", "aa:bb:cc:00:00:20",
			uint16(50130+i), 80, winChromeUA, "nginx", 128))
	}
	n := snapNodeByIP(e.Snapshot(), "192.168.31.100")
	if n == nil {
		t.Fatal("节点缺失")
	}
	if len(n.Software) != 1 || n.Software[0] != "nginx" {
		t.Fatalf("重复观测应只留一条，实际 %v", n.Software)
	}
}
