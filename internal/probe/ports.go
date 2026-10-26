package probe

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// 端口档位（借鉴灯塔 ARL 的「ALL / TOP1000 / TOP100」三档，但列表自持）。
//
// 为什么自带端口表而不依赖 nmap --top-ports：
//  1. 政务网/隔离内网的运维机上**常常装不了 nmap**（软件白名单、无外网源），
//     依赖它等于主动发现能力在真实环境里直接归零；
//  2. nmap 的 top-ports 是按公网服务频率排的，内网的有效端口分布完全不同
//     （445/3389/8080/3306 在内网远比 993/995 有价值）；
//  3. 端口表是纯数据，随二进制走，不需要任何外部文件。
//
// nmap 仍然保留，但只做「更准的服务版本识别」这一层（-sV），不再是能否扫描的前提。

// Profile 端口扫描档位。
const (
	ProfileQuick    = "quick"    // 约 100 个内网高价值端口，秒级完成
	ProfileStandard = "standard" // 1-1024 全部知名端口 + 常见高位端口（默认）
	ProfileFull     = "full"     // 1-65535 全端口
)

// quickPorts 内网高价值端口（约 100 个）。
// 排序按「内网出现概率 × 信息价值」：远程管理、文件共享、数据库、常见 Web 管理口优先。
var quickPorts = []int{
	// 远程管理与文件共享（内网最高频，也是最该被看见的）
	22, 23, 135, 139, 445, 3389, 5900, 5901, 5985, 5986,
	// Web / 中间件
	80, 81, 88, 443, 8000, 8008, 8009, 8080, 8081, 8082, 8088, 8090,
	8180, 8443, 8888, 9000, 9001, 9080, 9090, 9443, 10000,
	// 数据库与缓存
	1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 27018,
	// 消息与协调
	2181, 5672, 9092, 15672, 61616,
	// 目录与认证
	389, 636, 3268, 3269,
	// 邮件 / DNS / 时间 / 打印等基础设施
	25, 53, 110, 143, 465, 587, 993, 995, 123, 161, 162, 427, 515, 631,
	// 虚拟化 / 容器 / 运维平台
	2375, 2376, 2379, 2380, 6443, 10250, 5000, 5001, 8086, 9091,
	// 其他常见服务
	69, 111, 137, 138, 427, 548, 554, 623, 873, 902, 1080, 1099, 1701,
	1723, 1883, 2049, 3128, 3260, 4369, 5222, 5353, 5601, 5672, 5984,
	7001, 7002, 7070, 8083, 8084, 8085, 8500, 8529, 9042, 9418, 50000,
	50070,
}

// standardHighPorts 1-1024 之外的常见高位服务端口。
// 只补「已知有服务」的端口，不做 1025-65535 全扫——那是 full 档的事。
var standardHighPorts = []int{
	1080, 1099, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379, 2380,
	3000, 3260, 3268, 3269, 3306, 3389, 4369, 4444, 5000, 5001, 5222,
	5353, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 5985, 5986, 6000,
	6379, 6443, 7001, 7002, 7070, 7443, 8000, 8008, 8009, 8010, 8020,
	8030, 8040, 8050, 8060, 8070, 8080, 8081, 8082, 8083, 8084, 8085,
	8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8099, 8161, 8180,
	8181, 8200, 8222, 8300, 8400, 8443, 8480, 8500, 8529, 8530, 8531,
	8545, 8600, 8686, 8800, 8848, 8880, 8888, 8899, 8900, 8983, 9000,
	9001, 9002, 9042, 9080, 9081, 9090, 9091, 9092, 9100, 9200, 9300,
	9418, 9443, 9600, 9800, 9900, 9999, 10000, 10001, 10250, 10255,
	11211, 15672, 16379, 18080, 18081, 20000, 22122, 25565, 27017,
	27018, 28017, 50000, 50070, 50075, 50090, 61616,
}

// PortPlan 返回某档位要扫的端口（升序、去重）。
// 返回的 label 用于日志与界面提示，避免"扫了多少个端口"只存在于用户猜测里。
func PortPlan(profile string) (ports []int, label string, err error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", ProfileStandard:
		ports = make([]int, 0, 1100)
		for p := 1; p <= 1024; p++ {
			ports = append(ports, p)
		}
		ports = append(ports, standardHighPorts...)
		return dedupSorted(ports), "1-1024 + 常见高位端口", nil
	case ProfileQuick, "top100", "fast":
		return dedupSorted(append([]int(nil), quickPorts...)), "内网高价值端口", nil
	case ProfileFull, "all":
		ports = make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, "1-65535 全端口", nil
	default:
		return nil, "", fmt.Errorf("未知端口档位 %q（可选 quick|standard|full）", profile)
	}
}

func dedupSorted(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// WebPorts 常见 Web 服务端口：指纹阶段优先对它们发 HTTP/HTTPS 探测，
// 避免对每一个开放端口都发一次 HTTP 请求（65535 端口全发会变成一次小型 DoS）。
var webPorts = map[int]bool{
	80: true, 81: true, 82: true, 83: true, 84: true, 85: true, 86: true, 87: true, 88: true,
	443: true, 800: true, 888: true, 1000: true, 1080: true, 1883: true, 2000: true,
	3000: true, 3001: true, 4443: true, 5000: true, 5001: true, 5555: true, 5601: true,
	6000: true, 7001: true, 7002: true, 7070: true, 8000: true, 8008: true, 8009: true,
	8010: true, 8020: true, 8030: true, 8040: true, 8050: true, 8060: true, 8070: true,
	8080: true, 8081: true, 8082: true, 8083: true, 8084: true, 8085: true, 8086: true,
	8087: true, 8088: true, 8089: true, 8090: true, 8091: true, 8092: true, 8093: true,
	8161: true, 8180: true, 8181: true, 8200: true, 8222: true, 8300: true, 8400: true,
	8443: true, 8480: true, 8500: true, 8529: true, 8600: true, 8686: true, 8800: true,
	8848: true, 8880: true, 8888: true, 8899: true, 8900: true, 8983: true, 9000: true,
	9001: true, 9002: true, 9080: true, 9090: true, 9091: true, 9200: true, 9243: true,
	9443: true, 9600: true, 9800: true, 9900: true, 9999: true, 10000: true, 10001: true,
	10250: true, 15672: true, 18080: true, 18081: true, 20000: true, 28017: true,
	50000: true, 50070: true, 50075: true, 50090: true,
}

// tlsPorts 默认按 TLS 探测的端口（HTTPS 之外还有 LDAPS / IMAPS / SMTPS / RDP 等）。
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 989: true, 990: true, 992: true, 993: true, 994: true,
	995: true, 3269: true, 4443: true, 5061: true, 5986: true, 8443: true, 8531: true,
	8883: true, 9243: true, 9443: true, 10250: true,
}

// ---------- 速率限制 ----------

// limiter 全局令牌桶：主动扫描最容易出事的地方不是准确率，而是**把内网打出风暴**。
// 政务网里一台老交换机被 5000 pps 扫过去直接管理面失联，所以默认限速而非追求最快。
type limiter struct {
	mu     sync.Mutex
	rate   int // pps，0 表示不限
	next   time.Time
	nowFn  func() time.Time
	sleep  func(time.Duration)
	issued int64
	slept  time.Duration
}

func newLimiter(pps int) *limiter {
	return &limiter{rate: pps, nowFn: time.Now, sleep: time.Sleep}
}

// wait 取得一个发送许可；返回 false 表示上下文已取消。
// 用「下次可发送时刻」而非 ticker：ticker 在低频时会有空转与抖动，
// 且并发调用下需要额外加锁；这里用一次加锁算出应睡多久，简单且无累积误差。
func (l *limiter) wait(cancelled func() bool) bool {
	if l == nil || l.rate <= 0 {
		return !cancelled()
	}
	l.mu.Lock()
	now := l.nowFn()
	if l.next.IsZero() || now.After(l.next) {
		l.next = now
	}
	slot := l.next
	l.next = slot.Add(time.Second / time.Duration(l.rate))
	l.issued++
	l.mu.Unlock()

	d := slot.Sub(now)
	if d <= 0 {
		return !cancelled()
	}
	l.mu.Lock()
	l.slept += d
	l.mu.Unlock()
	l.sleep(d)
	return !cancelled()
}

// stats 返回已发放许可数与累计等待时长（测试与指标用）。
func (l *limiter) stats() (issued int64, slept time.Duration) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.issued, l.slept
}
