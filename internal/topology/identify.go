package topology

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"starmap/internal/geo"
	"starmap/internal/model"
)

// 设备角色识别（V1.5）。
//
// 解决的问题：拓扑只能告诉你"有这么一台机器、它和谁有流量"，回答不了
// "这台是什么设备"。接入真实网络后第一眼看到的就是这个问题——
// 192.168.31.1 明显是路由器、192.168.31.20 明显是 NAS，但图上两者长得一模一样，
// 只能靠人肉看 IP 去猜；更糟的是，路由器因为整天发 mDNS 被标成"一机两网"，
// NAS 因为整天上网被标成"反向代理"——设备身份缺失时，误报没有常识可以纠正。
//
// 识别原则：**只用被动观测到的证据，且证据要说得出处**。
//
//	角色    证据
//	------  ---------------------------------------------------------------
//	gateway 有主机把它的 MAC 当作公网出口的首跳（这是路由器的定义性行为）
//	dns     它作为服务端在 53 端口被访问过
//	nas     它提供文件共享（SMB/NFS/AFP/群晖 DSM），且确实有别的机器来连
//	db      它提供数据库端口，且有别的机器来连
//	web     它提供 Web 端口，且有别的机器来连
//	remote  它提供远程管理端口（RDP/SSH/VNC），且有别的机器来连
//	server  其它任意服务端口，且有别的机器来连
//	host    没有观测到任何人来连它（终端/哑设备）
//
// 注意"且有别的机器来连"这个条件：Windows 客户端默认也监听 445，如果只看端口
// 不看有没有人连，全公司的办公电脑都会被标成"NAS"。端口是"它在听"，
// 入向对端是"它真的在提供服务"，两个证据合起来才成立。

// 设备角色
const (
	RoleGateway  = "gateway"
	RoleNAS      = "nas"
	RoleDNS      = "dns"
	RoleDB       = "db"
	RoleWeb      = "web"
	RoleRemote   = "remote"
	RoleServer   = "server"
	RoleHost     = "host"
	RoleExternal = "external"
)

// RoleNames 角色中文名（前端展示用，API 里另给 role）。
var RoleNames = map[string]string{
	RoleGateway:  "网关/路由器",
	RoleNAS:      "存储/NAS",
	RoleDNS:      "DNS 服务器",
	RoleDB:       "数据库",
	RoleWeb:      "Web 站点",
	RoleRemote:   "远程管理",
	RoleServer:   "应用服务",
	RoleHost:     "终端",
	RoleExternal: "外网",
}

// inboundPeerCap 单节点入向对端去重上限。
// 只用于"有没有人在连它"这个布尔判断，没必要记全量，否则一台热门服务器
// 能把整张内网的对端 IP 都塞进内存。
const inboundPeerCap = 128

type svcInfo struct {
	Name string // 短标识，如 smb
	Hint string // 中文说明
}

// serviceCatalog 常见服务端口目录。
// 偏重国产环境里真实会遇到的东西：群晖 DSM、网康/深信服类管理口、
// 海康/大华的 RTSP、以及政务网里长期在跑的 WebLogic/Oracle。
var serviceCatalog = map[uint16]svcInfo{
	20:    {"ftp-data", "FTP 数据通道"},
	21:    {"ftp", "FTP 文件传输"},
	22:    {"ssh", "SSH 远程登录"},
	23:    {"telnet", "Telnet（明文协议）"},
	25:    {"smtp", "邮件发送"},
	53:    {"dns", "域名解析"},
	67:    {"dhcp", "DHCP 服务端"},
	69:    {"tftp", "TFTP"},
	80:    {"http", "Web（HTTP）"},
	88:    {"kerberos", "域认证"},
	111:   {"rpcbind", "RPC 端口映射"},
	123:   {"ntp", "时间同步"},
	135:   {"msrpc", "Windows RPC"},
	137:   {"netbios-ns", "NetBIOS 名称服务"},
	139:   {"netbios-ssn", "Windows 文件共享（NetBIOS）"},
	143:   {"imap", "邮件收取"},
	161:   {"snmp", "SNMP 设备管理"},
	389:   {"ldap", "目录服务"},
	443:   {"https", "Web（HTTPS）"},
	445:   {"smb", "Windows/Samba 文件共享"},
	465:   {"smtps", "加密邮件发送"},
	500:   {"isakmp", "IPSec VPN"},
	514:   {"syslog", "日志收集"},
	548:   {"afp", "macOS 文件共享"},
	554:   {"rtsp", "视频流（摄像头）"},
	587:   {"submission", "邮件提交"},
	623:   {"ipmi", "服务器带外管理"},
	631:   {"ipp", "网络打印"},
	636:   {"ldaps", "加密目录服务"},
	873:   {"rsync", "文件同步"},
	993:   {"imaps", "加密邮件收取"},
	1080:  {"socks", "SOCKS 代理"},
	1433:  {"mssql", "SQL Server"},
	1521:  {"oracle", "Oracle"},
	1883:  {"mqtt", "物联网消息"},
	2049:  {"nfs", "NFS 文件共享"},
	2181:  {"zookeeper", "ZooKeeper"},
	2375:  {"docker", "Docker 未加密 API"},
	2376:  {"docker-tls", "Docker API"},
	3000:  {"grafana", "Grafana"},
	3306:  {"mysql", "MySQL"},
	3389:  {"rdp", "Windows 远程桌面"},
	5000:  {"dsm", "群晖 DSM 管理 / UPnP"},
	5001:  {"dsm-https", "群晖 DSM 管理（HTTPS）"},
	5060:  {"sip", "VoIP 信令"},
	5432:  {"postgres", "PostgreSQL"},
	5601:  {"kibana", "Kibana"},
	5672:  {"amqp", "RabbitMQ"},
	5900:  {"vnc", "VNC 远程桌面"},
	6379:  {"redis", "Redis"},
	6443:  {"k8s-api", "Kubernetes API"},
	7001:  {"weblogic", "WebLogic"},
	8000:  {"http-alt", "Web（备用端口）"},
	8009:  {"ajp", "AJP 连接器"},
	8080:  {"http-alt", "Web（备用端口）"},
	8081:  {"http-alt", "Web（备用端口）"},
	8088:  {"http-alt", "Web（备用端口）"},
	8443:  {"https-alt", "Web（HTTPS 备用端口）"},
	8888:  {"http-alt", "Web（备用端口）"},
	9000:  {"app", "应用服务（MinIO/Portainer 等）"},
	9090:  {"prometheus", "Prometheus"},
	9200:  {"elasticsearch", "Elasticsearch"},
	9300:  {"elasticsearch", "Elasticsearch 集群"},
	11211: {"memcached", "Memcached"},
	27017: {"mongodb", "MongoDB"},
}

// 角色判定用的端口集合。
var (
	nasStrong   = map[uint16]bool{2049: true, 548: true, 5000: true, 5001: true} // 单见即成立
	nasWeak     = map[uint16]bool{445: true, 139: true}                          // 需 ≥2 个入向对端
	dnsPorts    = map[uint16]bool{53: true}
	dbPorts     = map[uint16]bool{1433: true, 1521: true, 3306: true, 5432: true, 6379: true, 9200: true, 11211: true, 27017: true, 5672: true, 1883: true}
	webPorts    = map[uint16]bool{80: true, 443: true, 8080: true, 8081: true, 8088: true, 8443: true, 8000: true, 8888: true}
	remotePorts = map[uint16]bool{22: true, 23: true, 3389: true, 5900: true, 512: true, 513: true}
)

// ServiceName 返回端口对应的服务短名（未知端口返回空串）。
func ServiceName(port int) string {
	if s, ok := serviceCatalog[uint16(port)]; ok {
		return s.Name
	}
	return ""
}

// ServiceHint 返回端口对应的中文说明。
func ServiceHint(port int) string {
	if s, ok := serviceCatalog[uint16(port)]; ok {
		return s.Hint
	}
	return ""
}

// isServicePort 判断端口是否值得记为"服务端口"。
// 服务端口 = 知名端口（<1024）或目录里点名的端口；客户端临时端口（40000+）一律不算，
// 否则每台机器都会"开着一堆端口"，角色识别就没意义了。
func isServicePort(port uint16) bool {
	if port == 0 {
		return false
	}
	if port < 1024 {
		return true
	}
	_, ok := serviceCatalog[port]
	return ok
}

// serviceLabels 把端口列表映射成 "端口/服务名" 形式的展示串。
func serviceLabels(ports []int) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if name := ServiceName(p); name != "" {
			out = append(out, strconv.Itoa(p)+"/"+name)
		} else {
			out = append(out, strconv.Itoa(p))
		}
	}
	return out
}

// roleEvidence 判定角色所需的全部证据。
//
// 之所以打包成结构体而不是一串参数：这里的每一项都对应一种"我们到底看见了什么"，
// 加参数时最容易被调用方漏填，而漏填的后果是静默少判或错判角色。
type roleEvidence struct {
	// Ports 被动观测到它作为服务端被访问过的端口。
	Ports []int
	// Peers 本次进程内主动连过它的对端数量。
	Peers int
	// GatewayFor 有多少台主机把它的 MAC 当作公网出口首跳。
	GatewayFor int
	// SeenSrc 本次进程内观测到它主动发过流量（判定"终端"的正面证据）。
	SeenSrc bool
	// Inbound 曾观测到有人连过它。与 Peers 的区别是它包含**跨重启恢复**的证据：
	// 端口库里 source=traffic 的记录说明历史上确实有会话打到过这个端口，
	// 而 Peers 只在内存里滚，进程重启就归零了。
	Inbound bool
}

// inferRoles 按证据推断设备角色，按"越具体越靠前"排序。
//
// 关键的一条：**没有证据不等于它是终端**。端口/对端这类证据只在内存里滚，
// 进程重启后归零；如果此时还硬判一个 host，就等于把一台正在提供 DNS 服务的
// 机器说成"普通终端"——用户按这个结论排查会直接走错方向。宁可返回空角色
// （前端显示"未识别"），也不要给一个没有依据的结论。
func inferRoles(ev roleEvidence) []string {
	ports := ev.Ports
	hasInbound := ev.Inbound || ev.Peers > 0
	var roles []string
	add := func(r string) { roles = append(roles, r) }
	has := func(set map[uint16]bool) bool {
		for _, p := range ports {
			if set[uint16(p)] {
				return true
			}
		}
		return false
	}

	if ev.GatewayFor > 0 {
		add(RoleGateway)
	}
	if hasInbound {
		// NAS：强特征端口（NFS/AFP/群晖 DSM）单见即成立；只有 445/139 时
		// 要求至少两台机器来连——一台 Windows 客户端也监听 445，但没人会去连它。
		if has(nasStrong) || (has(nasWeak) && ev.Peers >= 2) {
			add(RoleNAS)
		}
		if has(dnsPorts) {
			add(RoleDNS)
		}
		if has(dbPorts) {
			add(RoleDB)
		}
		if has(webPorts) {
			add(RoleWeb)
		}
		if has(remotePorts) {
			add(RoleRemote)
		}
	}
	// 有人在连它、也确实开着端口，但都不在已知集合 → 泛化的"应用服务"。
	if hasInbound && len(roles) == 0 && len(ports) > 0 {
		add(RoleServer)
	}
	// 只有"本次确实看到它主动发包"才敢说它是终端。
	if len(roles) == 0 && ev.SeenSrc {
		add(RoleHost)
	}
	return roles
}

// sortedPorts 返回排好序的端口列表（map 迭代无序，直接输出会让前端每次刷新都跳）。
func sortedPorts(set map[uint16]bool) []int {
	if len(set) == 0 {
		return nil
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, int(p))
	}
	sort.Ints(out)
	return out
}

// gatewayCountLocked 统计每个 MAC 被多少台主机当作公网出口的首跳。
// 调用方需持 e.mu。
func (e *Engine) gatewayCountLocked() map[string]int {
	out := make(map[string]int, len(e.gatewayMAC))
	for _, mac := range e.gatewayMAC {
		if mac != "" {
			out[mac]++
		}
	}
	return out
}

// observeServiceLocked 记录一次"某节点作为服务端被访问"的观测（调用方需持 e.mu）。
//
// 只记目的地址在内网、且目的端口是服务端口的会话——这才是"这台机器在提供服务"。
// 本机访问 114.114.114.114:53 不会被记进来：那说明它是 DNS **客户端**，
// 不说明它是 DNS **服务器**。这条区分正是接入真实网络后最先被质疑的地方
// （"31.20 是 NAS，怎么还有 DNS"——它只是在自己解析域名）。
func (e *Engine) observeServiceLocked(srcID, dstID int64, s *model.Session) {
	if !IsPrivate(s.FiveTuple.DstIP) || !isServicePort(s.FiveTuple.DstPort) {
		return
	}
	if srcID == dstID { // 本机自发自收，不构成对外服务
		return
	}
	set := e.ports[dstID]
	if set == nil {
		set = map[uint16]bool{}
		e.ports[dstID] = set
	}
	set[s.FiveTuple.DstPort] = true
	e.inboundSeen[dstID] = true

	peers := e.inboundPeers[dstID]
	if peers == nil {
		peers = map[string]struct{}{}
		e.inboundPeers[dstID] = peers
	}
	if len(peers) < inboundPeerCap {
		peers[s.FiveTuple.SrcIP] = struct{}{}
	}
}

// observeStackLocked 记录"系统栈 / 软件"层面的身份证据（调用方需持 e.mu）。
//
// 角色回答"它在干什么"，这一步回答"它是什么系统、装了什么软件"。两条证据来源：
//
//	证据                覆盖范围                    能给什么
//	------------------  --------------------------  ------------------------------
//	IP TTL              全部流量（含 TLS/VPN）       系统栈大类（Windows/类 Unix/网络设备）
//	HTTP UA / Server    仅明文 HTTP                 具体软件（nginx、群晖 DSM、iPhone…）
//
// TTL 只记最大值：它是"初始 TTL 减去转发跳数"，取最大值最接近原始值；
// 取最小值会把偶尔一个被多跳衰减的包当成系统指纹，越看越偏。
func (e *Engine) observeStackLocked(srcID, dstID int64, s *model.Session) {
	// 1) 栈指纹：TTL 属于会话发起方（StartTTL 取自首包）。
	// 只记内网节点：公网聚合节点背后是成百上千台不同的服务器，取最大值毫无意义。
	if s.StartTTL > 0 && IsPrivate(s.FiveTuple.SrcIP) {
		if s.StartTTL > e.ttlSeen[srcID] {
			e.ttlSeen[srcID] = s.StartTTL
		}
	}
	// 2) 软件指纹：UA 属于客户端、Server 头属于服务端，方向靠端口推断。
	// 两端都是服务端口时方向不可判（例如 80→8080 的同机反代），此时宁可不记，
	// 也不要把服务端的 nginx 记到一台客户端头上。
	srcSvc := isServicePort(s.FiveTuple.SrcPort)
	dstSvc := isServicePort(s.FiveTuple.DstPort)
	if srcSvc == dstSvc {
		return
	}
	clientID, serverID := srcID, dstID
	ua, srv := s.UserAgent, s.HTTPServer
	if srcSvc { // 源是服务端 → 方向反过来
		clientID, serverID = dstID, srcID
	}
	set := func(id int64, label string) {
		if label == "" || id == 0 || !e.isPrivateNodeLocked(id) {
			return
		}
		m := e.software[id]
		if m == nil {
			m = map[string]bool{}
			e.software[id] = m
		}
		if len(m) >= softwareCap && !m[label] {
			return
		}
		m[label] = true
	}
	set(clientID, uaLabel(ua))
	set(serverID, normalizeServer(srv))
}

// isPrivateNodeLocked 判断节点是否是内网设备（调用方需持 e.mu）。
// 网关这类只有 MAC、没有 IP 的节点也算内网设备。
func (e *Engine) isPrivateNodeLocked(id int64) bool {
	n := e.nodes[id]
	if n == nil {
		return false
	}
	if len(n.IPs) == 0 {
		return n.MAC != "" // 只有 MAC 的节点必然是本地链路设备（网关）
	}
	return IsPrivate(n.IPs[0])
}

// softwareCap 单节点软件标识上限（同一台机器可能跑很多站点，没必要全留）。
const softwareCap = 8

// maxLabelLen 单个软件标识最大长度：UA 和 Server 头都是对端可控文本，
// 原样透传到界面既会被超长串撑爆布局，也是把外部输入直接丢给前端的坏习惯。
const maxLabelLen = 60

// normalizeServer 清洗 Server / X-Powered-By 头。
func normalizeServer(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return truncateRunes(s, maxLabelLen)
}

// uaLabel 把 User-Agent 压成"系统 · 软件"的可读标签。
//
// 保留原始 UA 全文没有意义（动辄 150 字符，且 90% 是引擎版本噪声），要的是
// "这台机器是 Windows 还是 iPhone、用什么在访问"这个结论性信息。
func uaLabel(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ""
	}
	os := uaOS(ua)
	app := uaApp(ua)
	switch {
	case os != "" && app != "":
		return truncateRunes(os+" · "+app, maxLabelLen)
	case os != "":
		return os
	case app != "":
		return app
	}
	// 到这里说明 UA 里没有可用信息（典型的是裸 "Mozilla/5.0"，很多嵌入式
	// 客户端和脚本就这么发）。原样记下来只会给界面添一条噪声，不如不记。
	if isUselessUA(ua) {
		return ""
	}
	return truncateRunes(ua, maxLabelLen)
}

// isUselessUA 判断 UA 是否只是一句"我是浏览器"的空话。
func isUselessUA(ua string) bool {
	switch strings.TrimSpace(ua) {
	case "Mozilla/5.0", "Mozilla/4.0", "Mozilla", "-", "unknown":
		return true
	}
	return false
}

// uaOS 从 UA 里判定操作系统；判不出返回空串。
// 顺序敏感：Android 的 UA 里同时有 "Linux"，iPhone 的里面也有 "Mac OS X"。
func uaOS(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"):
		return "iOS"
	case strings.Contains(ua, "HarmonyOS"), strings.Contains(ua, "OpenHarmony"):
		return "鸿蒙"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Windows NT 10.0"):
		return "Windows 10/11"
	case strings.Contains(ua, "Windows NT 6.3"), strings.Contains(ua, "Windows NT 6.2"):
		return "Windows 8/8.1"
	case strings.Contains(ua, "Windows NT 6.1"):
		return "Windows 7"
	case strings.Contains(ua, "Windows NT 6.0"):
		return "Windows Vista"
	case strings.Contains(ua, "Windows NT 5.1"), strings.Contains(ua, "Windows XP"):
		return "Windows XP"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	// Windows 系统组件自报家门时不带 "Windows NT"：证书服务、BITS 下载、
	// 遥测上报都是这种 UA（如 "Microsoft-CryptoAPI/10.0"）。
	case strings.Contains(ua, "Microsoft-"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux"
	}
	return ""
}

// uaApp 从 UA 里判定客户端软件；判不出返回空串。
func uaApp(ua string) string {
	switch {
	case strings.Contains(ua, "MicroMessenger"):
		return "微信内置浏览器"
	case strings.Contains(ua, "Synology"), strings.Contains(ua, "DiskStation"):
		return "群晖客户端"
	case strings.Contains(ua, "curl/"):
		return "curl"
	case strings.Contains(ua, "Wget/"):
		return "wget"
	case strings.Contains(ua, "python-requests"), strings.Contains(ua, "Python-urllib"):
		return "Python 脚本"
	case strings.Contains(ua, "Go-http-client"):
		return "Go 客户端"
	case strings.Contains(ua, "PostmanRuntime"):
		return "Postman"
	case strings.Contains(ua, "sqlmap"):
		return "sqlmap"
	case strings.Contains(ua, "Edg/"):
		return withVer("Edge", uaVer(ua, "Edg/"))
	case strings.Contains(ua, "Firefox/"):
		return withVer("Firefox", uaVer(ua, "Firefox/"))
	case strings.Contains(ua, "Chrome/"):
		return withVer("Chrome", uaVer(ua, "Chrome/"))
	case strings.Contains(ua, "Safari/"):
		return withVer("Safari", uaVer(ua, "Version/"))
	}
	return ""
}

// withVer 拼"名称 版本"，版本缺失时不留尾空格。
func withVer(name, ver string) string {
	if ver == "" {
		return name
	}
	return name + " " + ver
}

// uaVer 取出 token 后的主版本号（"Chrome/120.0.1.2" → "120"）。
func uaVer(ua, token string) string {
	i := strings.Index(ua, token)
	if i < 0 {
		return ""
	}
	rest := ua[i+len(token):]
	end := 0
	for end < len(rest) && rest[end] != '.' && rest[end] != ' ' && rest[end] != ';' && rest[end] != ')' {
		end++
	}
	return rest[:end]
}

// truncateRunes 按字符（不是字节）截断，避免把多字节 UTF-8 切成半个字。
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// osHintFromTTL 用初始 TTL 推断系统栈大类（p0f 的粗粒度做法）。
//
// 这不是结论而是提示，必须连原始 TTL 一起展示：TTL 会随转发跳数递减，
// 一台 8 跳外的 Windows（128）在抓包点看到的是 120，仍落在 64<TTL≤128 里；
// 但一台 30 跳外的 Linux（64）会掉到 34，看起来就像"老式嵌入式设备"。
// 只在"内网直连、跳数很少"时可信，这也是本产品的主战场（政务网/隔离内网）。
func osHintFromTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl > 128:
		return "网络设备" // 路由器/交换机/打印机常见初始 TTL=255
	case ttl > 64:
		return "Windows"
	case ttl >= 33:
		return "类 Unix"
	default:
		// TTL ≤ 32：要么是初始 32 的老设备，要么是 64 被衰减了两轮以上，
		// 两种情况都无法区分，不猜。
		return ""
	}
}

// tunnelLabels 疑似隧道的标签，取值等于检测规则产出的类型名。
//
// 标签存在意味着"对应事件确实产生过一次"（detect 侧是 CreateEvent 成功后才
// AddNodeLabel），所以这里不是猜的，可以直接当作证据用于标红外置。
var tunnelLabels = []string{"frp", "clash"}

// IsTunnelSuspect 判断节点是否有"疑似隧道"证据（FRP / Clash 类客户端特征）。
func IsTunnelSuspect(n *model.Node) bool {
	for _, l := range n.Labels {
		for _, want := range tunnelLabels {
			if l == want {
				return true
			}
		}
	}
	return false
}

// restoreServiceEvidenceLocked 从端口库恢复"服务画像"证据（调用方需持 e.mu）。
//
// 为什么需要它：端口/对端/TTL/软件这些证据只在内存里滚，进程一重启就归零。
// 而拓扑节点本身是持久化的——结果是重启后节点还在、身份全变"未识别"，
// 用户会以为识别能力失效了。端口库里 source=traffic 的记录恰恰是
// "历史上确实有会话打到过这个端口"的持久化证据，用它把画像接回来。
//
// 只认 source=traffic：nmap 扫出来的开放端口只说明"它在听"，不说明有人连过，
// 用它恢复角色会把全网的 445 监听端都标成 NAS。
func (e *Engine) restoreServiceEvidenceLocked() {
	if e.persist == nil {
		return
	}
	ports, err := e.persist.ListPorts("", "")
	if err != nil {
		return // 端口库读不到只影响身份画像，不影响拓扑本身，不阻塞启动
	}
	for _, p := range ports {
		if p.Source != model.PortSourceTraffic {
			continue
		}
		id, ok := e.nodeKey[p.NodeKey]
		if !ok || e.nodes[id] == nil {
			continue
		}
		port := uint16(p.Port)
		if !isServicePort(port) {
			continue
		}
		set := e.ports[id]
		if set == nil {
			set = map[uint16]bool{}
			e.ports[id] = set
		}
		set[port] = true
		e.inboundSeen[id] = true
	}
}

// gatewayNodeLocked 返回网关 MAC 对应的节点，不存在则创建（调用方需持 e.mu）。
//
// 网关是内网里最该被看见的设备，但它在被动侧天然"隐身"：它的 IP 从不出现在
// 我们观测到的五元组里，能拿到的只有以太网头上的 MAC（公网流量的首跳下一跳）。
// 不为这个 MAC 建节点，图里就只剩一台台主机直接连向公网网段，中间那一跳消失——
// 这本身就是在撒谎：明明有一台设备在给全网上网做转发。
//
// 后续若同一 MAC 的主机真的产生了带 IP 的会话，nodeForLocked 会把该 IP 合并进来，
// 匿名网关节点自动变成有名有姓的设备。
func (e *Engine) gatewayNodeLocked(mac string, now time.Time) int64 {
	if mac == "" {
		return 0
	}
	if id, ok := e.macNode[mac]; ok {
		return id
	}
	// 复用已有身份：库存里可能已经有一条只带 MAC 的节点（例如上次进程写下的），
	// 直接接管它，避免同一台网关被拆成两行。
	key := "mac:" + mac
	if id, ok := e.nodeKey[key]; ok {
		e.macNode[mac] = id
		return id
	}
	// 分配空闲 ID：理论上 nextNodeID 已经越过所有既有节点，但网关节点是唯一
	// "不经过 nodeForLocked 创建"的节点，一旦 ID 与既有节点撞上就会把对方覆盖掉
	// （表现为那台设备凭空丢了 IP、历史边挂在了一个空壳上）。这里显式跳过占位。
	id := e.nextNodeID
	for e.nodes[id] != nil {
		id++
	}
	e.nextNodeID = id + 1
	n := &model.Node{
		ID:        id,
		NodeKey:   key,
		MAC:       mac,
		FirstSeen: now,
		LastSeen:  now,
		Active:    true,
		RiskLevel: model.RiskNone,
	}
	e.nodes[id] = n
	e.macNode[mac] = id
	e.nodeKey[key] = id
	e.dirtyNodes[id] = true
	return id
}

// gatewayEdgesLocked 生成"主机 → 网关"的出网路径边（调用方需持 e.mu）。
// 与真实流量边互斥：两者已经在图上相邻时不再重复连线。
func (e *Engine) gatewayEdgesLocked(existing []VisibleEdge) []VisibleEdge {
	if len(e.gatewayMAC) == 0 {
		return nil
	}
	visible := e.visibleMapLocked()
	paired := make(map[string]bool, len(existing)*2)
	for _, ed := range existing {
		paired[ed.Src+"|"+ed.Dst] = true
		paired[ed.Dst+"|"+ed.Src] = true
	}
	var out []VisibleEdge
	for clientID, mac := range e.gatewayMAC {
		gwID, ok := e.macNode[mac]
		if !ok {
			continue
		}
		src, okSrc := visible[clientID]
		dst, okDst := visible[gwID]
		if !okSrc || !okDst || src == dst {
			continue
		}
		if paired[src+"|"+dst] {
			continue
		}
		paired[src+"|"+dst] = true
		paired[dst+"|"+src] = true
		out = append(out, VisibleEdge{Src: src, Dst: dst, Protocol: "gateway", Kind: EdgeKindGateway, Active: true})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src < out[j].Src
		}
		return out[i].Dst < out[j].Dst
	})
	return out
}

// annotateIdentity 填充节点的身份字段（角色/服务/端口/入向对端/系统栈/软件/归属）。
// 调用方需持 e.mu；gw 为 gatewayCountLocked 的结果。
func (e *Engine) annotateIdentity(n *model.Node, gw map[string]int) {
	// 系统栈与软件两条证据先算：公网节点也要给（虽然角色只有"外网"，
	// 但"这台公网主机跑 nginx"同样是情报）。
	n.TTL = e.ttlSeen[n.ID]
	n.Software = sortedSoftware(e.software[n.ID])
	// 端口使用同样在公网节点上也要给："这个公网 /24 是被访问了 443 还是 80"
	// 是判断"正常上网"与"外联隧道"的第一手证据，比归属地更具体。
	n.OutPorts = topPortUse(e.outUse[n.ID])
	n.InPorts = topPortUse(e.inUse[n.ID])

	// 归属：只有公网地址才谈得上"国内/国外"。geo 判定不出时保持 false，
	// 前端据此标红的门槛是"确认国外"，不能因为"不知道"就变红。
	n.Overseas = false
	for _, ip := range n.IPs {
		if IsPrivate(ip) {
			continue
		}
		if overseas, known := geo.IsOverseas(ip); known {
			n.Overseas = overseas
			break
		}
	}

	if hasLabel(n, LabelExternalAg) {
		n.Role = RoleExternal
		n.Roles = []string{RoleExternal}
		n.OSHint = osHintFromTTL(n.TTL)
		return
	}
	ports := sortedPorts(e.ports[n.ID])
	peers := len(e.inboundPeers[n.ID])
	gwFor := 0
	if n.MAC != "" {
		gwFor = gw[n.MAC]
	}
	n.Ports = ports
	n.Services = serviceLabels(ports)
	n.InboundPeers = peers
	n.GatewayFor = gwFor
	n.Roles = inferRoles(roleEvidence{
		Ports:      ports,
		Peers:      peers,
		GatewayFor: gwFor,
		SeenSrc:    e.seenSrc[n.ID],
		Inbound:    e.inboundSeen[n.ID],
	})
	// 没有命中任何角色时留空，让前端显示"未识别"，而不是替用户下一个没依据的结论
	n.Role = ""
	if len(n.Roles) > 0 {
		n.Role = n.Roles[0]
	}
	// 系统栈：UA 里有明确系统名时以 UA 为准（TTL 只能给大类），否则退回 TTL 推断。
	n.OSHint = osHintFromSoftware(n.Software)
	if n.OSHint == "" {
		n.OSHint = osHintFromTTL(n.TTL)
	}
}

// osHintFromSoftware 从已经压成标签的软件列表里反查系统名。
func osHintFromSoftware(labels []string) string {
	for _, l := range labels {
		for _, os := range []string{"Windows 10/11", "Windows 8/8.1", "Windows 7", "Windows Vista", "Windows XP", "Windows", "macOS", "iOS", "Android", "鸿蒙", "ChromeOS", "Linux"} {
			if strings.HasPrefix(l, os) {
				return os
			}
		}
	}
	return ""
}

// sortedSoftware 返回排好序的软件标识（map 迭代无序，直接输出会让前端每次刷新都跳）。
func sortedSoftware(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
