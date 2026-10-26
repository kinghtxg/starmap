package probe

import (
	"regexp"
	"strings"
)

// 指纹规则库。
//
// 排序即优先级：越靠前的规则越"专属"（国产 OA / 网络设备 / 业务系统），
// 越靠后的越"泛化"（Web 服务器中间件）。命中即返回，避免出现
// "一个 Tomcat 页面同时被识别成 Apache + Tomcat + Java"这种含糊结论。
//
// 只保留"能指向具体产品"的规则：宁可不给结论，也不给错误结论——
// 资产台账里写错产品名比留空危害更大。

// ruleInput 规则匹配的输入（均已转小写）。
type ruleInput struct {
	header string // 响应头 + 状态行
	body   string // 响应体（限长）
	banner string // 原始 banner
	title  string // 页面标题（小写）
	port   int
}

type fpRule struct {
	Product string   // 产品名（给人看的）
	Service string   // 归一化服务名（给程序用的：http/ssh/mysql/...）
	Any     []string // header / body / banner 中任一出现即命中
	Title   []string // 标题包含任一即命中
	Header  []string // 只在响应头里匹配（语义上更明确，匹配范围同上）
	Ports   []int    // 限定端口（可选）
	Version string   // 版本提取正则（第 1 个分组为版本号）
	verRE   *regexp.Regexp
}

var fpRules = []fpRule{
	// ---------- 国产 / 内网高价值业务系统 ----------
	// 这类系统在政务网里是"最该被看见"的资产，且大多没有默认首页标题，
	// 只能靠静态资源路径识别——所以路径匹配比标题匹配更可靠。
	{Product: "深信服 SSL VPN", Service: "http", Any: []string{"/por/login_psw.csp", "sangfor"}, Title: []string{"深信服", "sangfor"}},
	{Product: "深信服 上网行为管理", Service: "http", Any: []string{"/ac_user/", "ac-webbui", "ac_login"}},
	{Product: "奇安信 天擎", Service: "http", Any: []string{"qianxin", "skylar", "360天擎"}},
	{Product: "泛微 e-cology", Service: "http", Any: []string{"/wui/index.html", "ecology_jsessionid", "/weaver/", "weaver"}, Title: []string{"泛微", "e-cology"}},
	{Product: "泛微 e-office", Service: "http", Any: []string{"/eoffice", "eoffice10"}},
	{Product: "致远 OA", Service: "http", Any: []string{"/seeyon/", "seeyon", "seeyon_jsessionid"}},
	{Product: "通达 OA", Service: "http", Any: []string{"/general/login", "/general/index", "tongda"}, Title: []string{"通达"}},
	{Product: "蓝凌 OA", Service: "http", Any: []string{"/sys/ui/extend/", "landray", "/km/review/"}},
	{Product: "用友 NC", Service: "http", Any: []string{"/nc/servlet/", "yonyou", "/uap/", "nccloud"}},
	{Product: "金蝶 EAS", Service: "http", Any: []string{"/easweb/", "kingdee"}},
	{Product: "帆软 FineReport", Service: "http", Any: []string{"finereport", "/webroot/decision"}},
	{Product: "宝塔面板", Service: "http", Any: []string{"bt-panel", "宝塔"}, Title: []string{"宝塔"}},
	{Product: "RuoYi 后台", Service: "http", Any: []string{"ruoyi"}, Title: []string{"ruoyi", "若依"}},
	{Product: "Nacos", Service: "http", Any: []string{"nacos"}, Title: []string{"nacos"}},
	{Product: "Apache APISIX", Service: "http", Header: []string{"server: apisix"}, Any: []string{"apisix"}},
	{Product: "Jenkins", Service: "http", Any: []string{"jenkins"}, Title: []string{"dashboard [jenkins]"}},
	{Product: "GitLab", Service: "http", Any: []string{"gitlab"}},
	{Product: "Grafana", Service: "http", Any: []string{"grafana"}},
	{Product: "Kibana", Service: "http", Any: []string{"kibana"}},
	{Product: "Prometheus", Service: "http", Any: []string{"prometheus"}, Title: []string{"prometheus"}},
	{Product: "Elasticsearch", Service: "elasticsearch", Any: []string{"you know, for search", "elasticsearch"}, Ports: []int{9200, 9300}},
	{Product: "RabbitMQ 管理台", Service: "http", Any: []string{"rabbitmq"}},
	{Product: "MinIO", Service: "http", Any: []string{"minio"}, Title: []string{"minio console"}},
	{Product: "Harbor", Service: "http", Any: []string{"harbor"}, Title: []string{"harbor"}},
	{Product: "SonarQube", Service: "http", Any: []string{"sonarqube", "sonar"}},
	{Product: "Zabbix", Service: "http", Any: []string{"zabbix"}},
	{Product: "phpMyAdmin", Service: "http", Any: []string{"phpmyadmin"}},
	{Product: "Spring Boot", Service: "http", Title: []string{"whitelabel error page"}, Any: []string{"whitelabel error page"}},
	{Product: "ThinkPHP", Service: "http", Any: []string{"thinkphp", "think_exception"}},

	// ---------- 网络设备 / 安防设备 ----------
	// 这些设备的管理页面往往就在 80/443 上，是内网横向移动的首选跳板，
	// 被当成"普通 Web 服务器"记进台账就失去了告警价值。
	{Product: "海康威视 设备", Service: "http", Any: []string{"hikvision", "dvrdvs", "doc/page/login.asp"}},
	{Product: "大华 设备", Service: "http", Any: []string{"dahua", "webshellclient"}},
	{Product: "Cisco 设备", Service: "http", Any: []string{"cisco systems", "cisco ios", "cisco adaptive"}, Header: []string{"www-authenticate: basic realm=\"level_15"}},
	{Product: "H3C 设备", Service: "http", Any: []string{"h3c", "comware"}},
	{Product: "华为 设备", Service: "http", Any: []string{"huawei", "eudemon", "quidway"}},
	{Product: "锐捷 设备", Service: "http", Any: []string{"ruijie", "rg-os"}},
	{Product: "TP-Link 设备", Service: "http", Any: []string{"tp-link"}},
	{Product: "D-Link 设备", Service: "http", Any: []string{"d-link"}},
	{Product: "CUPS 打印服务", Service: "http", Any: []string{"cups/"}, Title: []string{"cups"}},

	// ---------- Java / 中间件 ----------
	{Product: "WebLogic", Service: "http", Any: []string{"weblogic"}, Header: []string{"wl-request"}},
	{Product: "WebSphere", Service: "http", Any: []string{"websphere"}},
	{Product: "JBoss", Service: "http", Any: []string{"jboss"}},
	{Product: "Apache Tomcat", Service: "http", Any: []string{"tomcat"}, Title: []string{"tomcat"}},
	{Product: "Jetty", Service: "http", Header: []string{"server: jetty"}},

	// ---------- Web 服务器（泛化，放最后）----------
	{Product: "OpenResty", Service: "http", Any: []string{"openresty"}, Version: `openresty/([0-9][0-9a-z.\-]*)`},
	{Product: "nginx", Service: "http", Any: []string{"nginx/"}, Version: `nginx/([0-9][0-9a-z.\-]*)`},
	{Product: "Caddy", Service: "http", Header: []string{"server: caddy"}},
	{Product: "lighttpd", Service: "http", Any: []string{"lighttpd/"}, Version: `lighttpd/([0-9][0-9a-z.\-]*)`},
	{Product: "Microsoft IIS", Service: "http", Any: []string{"microsoft-iis"}, Version: `microsoft-iis/([0-9][0-9a-z.\-]*)`},
	{Product: "Apache httpd", Service: "http", Any: []string{"apache/"}, Version: `apache/([0-9][0-9a-z.\-]*)`},

	// ---------- 非 HTTP 服务（靠 banner 识别）----------
	{Product: "OpenSSH", Service: "ssh", Any: []string{"ssh-2.0-openssh_", "ssh-1.99-openssh_"}, Version: `openssh_([0-9][0-9a-z.]*)`},
	{Product: "SSH", Service: "ssh", Any: []string{"ssh-2.0-", "ssh-1.99-", "ssh-1.5-"}},
	{Product: "vsftpd", Service: "ftp", Any: []string{"vsftpd"}, Version: `vsftpd ([0-9][0-9a-z.]*)`},
	{Product: "ProFTPD", Service: "ftp", Any: []string{"proftpd"}, Version: `proftpd ([0-9][0-9a-z.]*)`},
	{Product: "Microsoft FTP", Service: "ftp", Any: []string{"microsoft ftp service"}},
	{Product: "Postfix", Service: "smtp", Any: []string{"postfix"}},
	{Product: "Exim", Service: "smtp", Any: []string{"exim"}, Version: `exim ([0-9][0-9a-z.]*)`},
	{Product: "Microsoft Exchange", Service: "smtp", Any: []string{"microsoft esmtp"}},
	{Product: "Sendmail", Service: "smtp", Any: []string{"sendmail"}},
	{Product: "SMTP", Service: "smtp", Any: []string{"esmtp", "smtp ready"}},
	{Product: "Dovecot", Service: "imap", Any: []string{"dovecot"}},
	{Product: "MariaDB", Service: "mysql", Any: []string{"-mariadb"}, Version: `([0-9][0-9.]*)-mariadb`},
	{Product: "MySQL", Service: "mysql", Any: []string{"mysql", "mysql_native_password"}},
	{Product: "Redis", Service: "redis", Any: []string{"+pong", "redis_version", "-noauth"}},
	{Product: "Memcached", Service: "memcached", Ports: []int{11211}, Any: []string{"version "}, Version: `version ([0-9][0-9.]*)`},
	{Product: "ZooKeeper", Service: "zookeeper", Ports: []int{2181, 2182}, Any: []string{"zookeeper version"}, Version: `zookeeper version: ([0-9][0-9a-z.\-]*)`},
	{Product: "VNC", Service: "vnc", Any: []string{"rfb 0"}, Version: `rfb ([0-9.]+)`},
	{Product: "rsync", Service: "rsync", Any: []string{"@rsyncd:"}, Version: `@rsyncd: ([0-9.]+)`},
	{Product: "Docker Registry", Service: "docker-registry", Header: []string{"docker-distribution-api-version"}},
	{Product: "Kubernetes API", Service: "kubernetes", Any: []string{"gitversion"}, Ports: []int{6443, 8443, 10250}},
	{Product: "etcd", Service: "etcd", Any: []string{"etcdserver"}, Ports: []int{2379, 2380}},
}

func init() {
	for i := range fpRules {
		if fpRules[i].Version == "" {
			continue
		}
		re, err := regexp.Compile(fpRules[i].Version)
		if err != nil {
			// 规则写错是开发期问题：直接 panic 让 CI 拦住，而不是静默少匹配一个版本号
			panic("probe: 指纹规则版本正则非法 [" + fpRules[i].Product + "]: " + err.Error())
		}
		fpRules[i].verRE = re
	}
}

// matchRules 返回 (产品名, 版本, 服务名)；未命中时三者均为空。
func matchRules(in ruleInput) (product, version, service string) {
	all := in.header + "\n" + in.body + "\n" + in.banner
	for i := range fpRules {
		r := &fpRules[i]
		if len(r.Ports) > 0 && !intIn(r.Ports, in.port) {
			continue
		}
		if !ruleHit(r, all, in.title) {
			continue
		}
		v := ""
		if r.verRE != nil {
			if m := r.verRE.FindStringSubmatch(all); len(m) > 1 {
				v = m[1]
			}
		}
		return r.Product, v, r.Service
	}
	return "", "", ""
}

func ruleHit(r *fpRule, all, title string) bool {
	for _, s := range r.Any {
		if strings.Contains(all, s) {
			return true
		}
	}
	for _, s := range r.Title {
		if strings.Contains(title, s) {
			return true
		}
	}
	for _, s := range r.Header {
		if strings.Contains(all, s) {
			return true
		}
	}
	return false
}

func intIn(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// serviceByPort 端口到服务名的兜底映射（没有任何指纹命中时用）。
var serviceByPort = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
	80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios",
	138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 162: "snmptrap",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "lpd",
	548: "afp", 587: "smtp", 623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync",
	902: "vmware", 993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmi",
	1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
	2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd",
	3260: "iscsi", 3268: "ldap-gc", 3269: "ldap-gc-tls", 3306: "mysql", 3389: "rdp",
	4369: "epmd", 5000: "http", 5222: "xmpp", 5353: "mdns", 5432: "postgres",
	5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
	5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes",
	7001: "weblogic", 8009: "ajp", 8080: "http", 8443: "https", 8500: "consul",
	8529: "arangodb", 9000: "http", 9042: "cassandra", 9090: "http", 9092: "kafka",
	9200: "elasticsearch", 9300: "elasticsearch", 9418: "git", 9443: "https",
	10250: "kubelet", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
	27018: "mongodb", 50000: "db2", 50070: "hdfs", 61616: "activemq",
}

// guessService 服务名兜底推断：端口表优先，Web 兜底按是否 TLS 区分。
func guessService(port int, isWeb, isTLS bool) string {
	if s, ok := serviceByPort[port]; ok {
		return s
	}
	if isWeb {
		if isTLS {
			return "https"
		}
		return "http"
	}
	if isTLS {
		return "tls"
	}
	return ""
}
