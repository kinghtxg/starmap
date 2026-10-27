// Package probe 主动探测：ARP / ICMP / Traceroute（SPEC §4 默认关闭，配置开关）。
// 跨平台实现：
//   - Linux：ping/traceroute 命令 + /proc/net/arp；
//   - Windows：ping/tracert 命令 + `arp -a`。
//
// 无命令/无权限时优雅降级，绝不 panic。
package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"starmap/internal/topology"
)

// goos 当前操作系统（包级变量，测试可覆盖以验证平台分支）。
var goos = runtime.GOOS

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

	// 内置 TCP 扫描的限速状态（见 connect.go / ports.go）。
	// mu 只保护这两个字段：限速器本身有独立的锁，避免热路径上互相等待。
	mu          sync.Mutex
	limit       *limiter
	defaultRate int

	// dial 可注入（测试用）；nil 时走 net.Dialer。
	dial func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error)

	// NowFunc 可注入时钟（测试用）
	NowFunc func() time.Time
	// lookPath / run 可注入（测试用）
	lookPath func(string) (string, error)
	run      func(name string, args ...string) (string, error)
}

// DefaultRatePPS 内置扫描的默认全局速率上限。
// 800 pps 是保守值：/24 网段 × 100 端口 ≈ 2.5 万个连接，约 30 秒发完，
// 对老交换机的管理面冲击可接受；追求速度可以在配置里显式调高。
const DefaultRatePPS = 800

// New 创建探测器（默认关闭）。
func New(eng *topology.Engine) *Scanner {
	return &Scanner{
		Engine:      eng,
		NowFunc:     time.Now,
		defaultRate: DefaultRatePPS,
		lookPath:    exec.LookPath,
		run: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
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

// arpScan ARP 探测：先并发 ping 触发 ARP 解析，再读系统 ARP 表。
// target 可为单 IP 或 /24 等 CIDR（最多 254 个主机地址）。
func (s *Scanner) arpScan(target string, res *Result) error {
	ips, err := expandTarget(target, 254)
	if err != nil {
		return err
	}
	// 触发 ARP 解析：并发 ping 一遍（尽力而为）
	if _, err := s.lookPath("ping"); err == nil {
		s.pingHosts(ips, 32)
	} else {
		res.Degraded = true
		res.Message = "系统无 ping 命令，仅读取现有 ARP 表"
	}
	// 读取系统 ARP 表（跨平台）
	table := s.readARPTable()
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

// pingHosts 并发 ping 目标（限制并发数，避免 /24 扫描串行过慢）。
func (s *Scanner) pingHosts(ips []string, concurrency int) {
	if concurrency <= 0 {
		concurrency = 32
	}
	args := pingArgs(1, 1)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_, _ = s.run("ping", append(append([]string{}, args...), ip)...)
		}()
	}
	wg.Wait()
}

// pingSweep 并发 ping 网段，返回存活主机 IP 列表（每个目标 1 包，快速扫描）。
func (s *Scanner) pingSweep(ips []string, concurrency int) []string {
	if concurrency <= 0 {
		concurrency = 32
	}
	args := pingArgs(1, 1)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var alive []string
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out, _ := s.run("ping", append(append([]string{}, args...), ip)...)
			if isPingAlive(out) {
				mu.Lock()
				alive = append(alive, ip)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return alive
}

// icmpPing ICMP 探测：系统 ping 兜底。支持单 IP / 主机名 / CIDR 网段。
func (s *Scanner) icmpPing(target string, res *Result) error {
	target = strings.TrimSpace(target)
	if _, err := s.lookPath("ping"); err != nil {
		res.Degraded = true
		return fmt.Errorf("环境无 ping 命令且无原始套接字权限，ICMP 探测不可用: %w", err)
	}

	// 展开目标：单 IP / CIDR 网段
	ips, err := expandTarget(target, 254)
	if err != nil {
		// 非 IP/CIDR：尝试主机名
		if _, lerr := net.LookupHost(target); lerr != nil {
			return fmt.Errorf("目标 %q 无法解析", target)
		}
		ips = []string{target}
	}

	// 单目标：3 包探测，保留 Raw
	if len(ips) == 1 {
		args := append(pingArgs(3, 2), ips[0])
		out, err := s.run("ping", args...)
		res.Raw = out
		if err != nil {
			return fmt.Errorf("ping 失败（目标不可达或权限不足）: %v", err)
		}
		if isPingAlive(out) {
			res.Hosts = append(res.Hosts, HostHit{IP: ips[0]})
		}
		return nil
	}

	// 网段：并发 ping 扫描（每个目标 1 包）
	alive := s.pingSweep(ips, 32)
	for _, ip := range alive {
		res.Hosts = append(res.Hosts, HostHit{IP: ip})
	}
	if len(alive) == 0 {
		res.Message = "网段内无存活主机（或 ICMP 被防火墙拦截）"
	}
	return nil
}

// traceroute 路由跟踪：Linux 用 traceroute，Windows 用 tracert；均失败时降级。
func (s *Scanner) traceroute(target string, res *Result) error {
	if goos == "windows" {
		if _, err := s.lookPath("tracert"); err == nil {
			out, err := s.run("tracert", "-d", "-h", "15", "-w", "1000", target)
			res.Raw = out
			res.Hosts = parseTracertWindows(out)
			return err
		}
		res.Degraded = true
		return errors.New("环境无 tracert 命令，路由跟踪不可用")
	}

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

// pingArgs 构造 ping 参数（count 个包，timeoutSec 秒超时，跨平台）。
func pingArgs(count, timeoutSec int) []string {
	if goos == "windows" {
		return []string{"-n", strconv.Itoa(count), "-w", strconv.Itoa(timeoutSec * 1000)}
	}
	return []string{"-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutSec)}
}

// isPingAlive 判断 ping 输出是否表明目标存活（跨平台关键字）。
func isPingAlive(out string) bool {
	lower := strings.ToLower(out)
	for _, kw := range []string{"ttl=", "bytes from", "reply from", "来自"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// readARPTable 读取系统 ARP 表（跨平台）。
func (s *Scanner) readARPTable() map[string]string {
	if goos == "windows" {
		return s.readARPTableWindows()
	}
	return readARPTableLinux()
}

// readARPTableLinux 读 /proc/net/arp（无需特权）。
func readARPTableLinux() map[string]string {
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

// readARPTableWindows 执行 `arp -a` 并解析（IP 行首、MAC 用 `-` 分隔）。
func (s *Scanner) readARPTableWindows() map[string]string {
	out := map[string]string{}
	raw, err := s.run("arp", "-a")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		for _, f := range fields[1:] {
			if !isMACWindows(f) {
				continue
			}
			mac := normalizeMAC(f)
			// 过滤广播/全零 MAC（非真实主机）
			if mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
				break
			}
			out[ip.String()] = mac
			break
		}
	}
	return out
}

// isMACWindows 判断形如 00-11-22-33-44-55 的 Windows MAC 表示。
func isMACWindows(s string) bool {
	if len(s) != 17 || !strings.Contains(s, "-") {
		return false
	}
	for i, c := range s {
		if i%3 == 2 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// normalizeMAC 把 Windows 的 `-` 分隔 MAC 归一化为 `:` 分隔（与 Linux 表一致）。
func normalizeMAC(s string) string { return strings.ReplaceAll(s, "-", ":") }

// expandTarget 展开目标：单 IP 或 IPv4 CIDR。
// limit 为「可用主机地址数」上限（去网络号与广播号后）。修复 P1-3：
// /24（254 主机）应允许，超大网段（如 /8）拒绝。
func expandTarget(target string, limit int) ([]string, error) {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}
	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("非法目标 %q：需为 IP 或 CIDR", target)
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("仅支持 IPv4 网段目标（IPv6 请指定单 IP）")
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones

	// 可用主机数：/31、/32 为点对点，无网络号/广播号概念
	hostCount := int64(1) << uint(hostBits)
	first := 0
	if hostBits >= 2 {
		hostCount -= 2
		first = 1
	}
	if hostCount > int64(limit) {
		return nil, fmt.Errorf("目标网段过大（%d 个可用主机地址，超过上限 %d），拒绝扫描", hostCount, limit)
	}

	// 展开可用主机地址（跳过网络号，止于广播号之前）
	ip := append(net.IP(nil), ipnet.IP.Mask(ipnet.Mask)...)
	addN(ip, uint32(first))
	ips := make([]string, 0, hostCount)
	for i := int64(0); i < hostCount; i++ {
		ips = append(ips, ip.String())
		addN(ip, 1)
	}
	return ips, nil
}

// addN 对 IPv4 地址做大端无符号递增。
func addN(ip net.IP, n uint32) {
	v4 := ip.To4()
	if len(v4) != 4 {
		return
	}
	v := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	v += n
	v4[0] = byte(v >> 24)
	v4[1] = byte(v >> 16)
	v4[2] = byte(v >> 8)
	v4[3] = byte(v)
}

// parseTraceroute 解析 Linux traceroute -n 输出中的跳数与 IP。
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

// parseTracertWindows 解析 Windows tracert -d 输出（行首跳数、行尾 IP）。
func parseTracertWindows(out string) []HostHit {
	var hits []HostHit
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hop, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		last := fields[len(fields)-1]
		if net.ParseIP(last) != nil {
			hits = append(hits, HostHit{IP: last, Hop: hop})
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
