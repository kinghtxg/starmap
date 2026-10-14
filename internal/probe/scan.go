// Package probe 主动探测：ARP / ICMP / Traceroute（SPEC §4 默认关闭，配置开关）。
// 容器内无原始套接字权限时优雅降级：优先系统命令（ping/traceroute/arp 表），
// 全部不可用时返回带说明的错误，绝不 panic。
package probe

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"starmap/internal/topology"
)

// ErrDisabled 探测开关未开启
var ErrDisabled = errors.New("主动探测未启用（请在配置中开启 probe_enabled）")

// Result 一次探测的结果
type Result struct {
	Type      string    `json:"Type"`
	Target    string    `json:"Target"`
	Hosts     []HostHit `json:"Hosts"`
	Raw       string    `json:"Raw,omitempty"`
	Degraded  bool      `json:"Degraded"` // 是否走了兜底路径
	Message   string    `json:"Message,omitempty"`
	StartedAt time.Time `json:"StartedAt"`
	Duration  string    `json:"Duration"`
}

// HostHit 探测发现的存活主机
type HostHit struct {
	IP  string `json:"IP"`
	MAC string `json:"MAC,omitempty"`
	Hop int    `json:"Hop,omitempty"` // traceroute 跳数
}

// Scanner 主动探测器
type Scanner struct {
	Engine *topology.Engine

	enabled atomic.Bool
	// NowFunc 可注入时钟（测试用）
	NowFunc func() time.Time
	// lookPath / run 可注入（测试用）
	lookPath func(string) (string, error)
	run      func(name string, args ...string) (string, error)
}

// New 创建探测器（默认关闭）。
func New(eng *topology.Engine) *Scanner {
	return &Scanner{
		Engine:   eng,
		NowFunc:  time.Now,
		lookPath: exec.LookPath,
		run: func(name string, args ...string) (string, error) {
			ctx, cancel := exec.Command(name, args...), func() {}
			_ = cancel
			out, err := ctx.CombinedOutput()
			return string(out), err
		},
	}
}

// SetEnabled 设置开关（配置联动）。
func (s *Scanner) SetEnabled(v bool) { s.enabled.Store(v) }

// Enabled 查询开关。
func (s *Scanner) Enabled() bool { return s.enabled.Load() }

// Trigger 触发一次探测；type ∈ {arp, icmp, traceroute}。
func (s *Scanner) Trigger(kind, target string) (*Result, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	start := s.NowFunc()
	res := &Result{Type: kind, Target: target, StartedAt: start}
	var err error
	switch strings.ToLower(kind) {
	case "arp":
		err = s.arpScan(target, res)
	case "icmp":
		err = s.icmpPing(target, res)
	case "traceroute":
		err = s.traceroute(target, res)
	default:
		return nil, fmt.Errorf("非法探测类型 %q：仅支持 arp|icmp|traceroute", kind)
	}
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		res.Message = err.Error()
	}
	// 结果注入拓扑引擎
	if s.Engine != nil {
		now := s.NowFunc()
		for _, h := range res.Hosts {
			s.Engine.ObserveHost(h.IP, h.MAC, now)
		}
	}
	return res, err
}

// arpScan ARP 探测：优先 arping；无权限/无命令时降级为"ping 触发 + 读 ARP 表"。
// target 可为单 IP 或 /24 CIDR（CIDR 时限制最多扫 254 台）。
func (s *Scanner) arpScan(target string, res *Result) error {
	ips, err := expandTarget(target, 254)
	if err != nil {
		return err
	}
	// 触发 ARP 解析：先 ping 一遍（尽力而为）
	if _, err := s.lookPath("ping"); err == nil {
		for _, ip := range ips {
			_, _ = s.run("ping", "-c", "1", "-W", "1", ip)
		}
	} else {
		res.Degraded = true
		res.Message = "系统无 ping 命令，仅读取现有 ARP 表"
	}
	// 读取系统 ARP 表（/proc/net/arp 无需特权）
	table := readARPTable()
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	for ip, mac := range table {
		if want[ip] {
			res.Hosts = append(res.Hosts, HostHit{IP: ip, MAC: mac})
		}
	}
	if len(res.Hosts) == 0 && res.Message == "" {
		res.Message = "ARP 表无目标条目（目标可能不可达或无权限触发解析）"
	}
	return nil
}

// icmpPing ICMP 探测：系统 ping 兜底（无原始套接字权限也可工作）。
func (s *Scanner) icmpPing(target string, res *Result) error {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		// 允许主机名
		if _, err := net.LookupHost(target); err != nil {
			return fmt.Errorf("目标 %q 无法解析", target)
		}
	}
	if _, err := s.lookPath("ping"); err != nil {
		res.Degraded = true
		return fmt.Errorf("环境无 ping 命令且无原始套接字权限，ICMP 探测不可用: %w", err)
	}
	out, err := s.run("ping", "-c", "3", "-W", "2", target)
	res.Raw = out
	if err != nil {
		return fmt.Errorf("ping 失败（目标不可达或权限不足）: %v", err)
	}
	// 有回包即存活
	if strings.Contains(out, "bytes from") || strings.Contains(out, "ttl=") || strings.Contains(out, "TTL=") {
		res.Hosts = append(res.Hosts, HostHit{IP: target})
	}
	return nil
}

// traceroute 路由跟踪：优先系统 traceroute（UDP 兜底 -U），无命令时降级为
// "ping -R（记录路由）"或直接报错说明。
func (s *Scanner) traceroute(target string, res *Result) error {
	if _, err := s.lookPath("traceroute"); err == nil {
		out, err := s.run("traceroute", "-n", "-U", "-w", "1", "-m", "15", target) // UDP 模式兜底
		res.Raw = out
		hops := parseTraceroute(out)
		if len(hops) > 0 {
			res.Hosts = hops
			return err
		}
		if err != nil {
			// UDP 被拦截时尝试 ICMP 模式
			out2, err2 := s.run("traceroute", "-n", "-I", "-w", "1", "-m", "15", target)
			res.Raw += out2
			res.Hosts = parseTraceroute(out2)
			res.Degraded = true
			return err2
		}
		return nil
	}
	// 无 traceroute 命令：降级 ping -R
	res.Degraded = true
	if _, err := s.lookPath("ping"); err == nil {
		out, err := s.run("ping", "-c", "1", "-R", target)
		res.Raw = out
		res.Hosts = parsePingRecordRoute(out)
		res.Message = "环境无 traceroute 命令，降级为 ping -R（记录路由）"
		return err
	}
	return errors.New("环境无 traceroute/ping 命令，路由跟踪不可用")
}

// expandTarget 展开目标：单 IP 或 CIDR（限制数量）。
func expandTarget(target string, limit int) ([]string, error) {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}
	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("非法目标 %q：需为 IP 或 CIDR", target)
	}
	var ips []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) > limit+1 {
			return nil, fmt.Errorf("目标网段过大（超过 %d 地址），拒绝扫描", limit)
		}
	}
	// 去掉网络地址与广播地址
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readARPTable 读取 /proc/net/arp（无需特权）。
func readARPTable() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 {
			out[fields[0]] = fields[3]
		}
	}
	return out
}

// parseTraceroute 解析 traceroute -n 输出中的跳数与 IP。
func parseTraceroute(out string) []HostHit {
	var hits []HostHit
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hop, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		for _, f := range fields[1:] {
			if f == "*" {
				continue
			}
			if net.ParseIP(f) != nil {
				hits = append(hits, HostHit{IP: f, Hop: hop})
				break
			}
		}
	}
	return hits
}

// parsePingRecordRoute 解析 ping -R 输出中的 RR 记录 IP。
func parsePingRecordRoute(out string) []HostHit {
	var hits []HostHit
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RR:") || strings.HasPrefix(line, "RR") {
			for _, f := range strings.Fields(strings.TrimPrefix(line, "RR:")) {
				if net.ParseIP(f) != nil {
					hits = append(hits, HostHit{IP: f})
				}
			}
		}
	}
	return hits
}
