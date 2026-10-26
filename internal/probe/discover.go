package probe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// 主动发现编排器：把"扫端口"和"认服务"串成一条可长期无人值守运行的流水线。
//
// 编排层解决的是**顺序与代价**问题，而不是扫描算法本身：
//   1. 先按档位扫端口（便宜、覆盖广），只有真的开了端口才做指纹（贵、慢）；
//   2. 指纹只挑"最可能说明身份"的端口（TLS 证书 / Web / 已知服务），
//      绝不把 65535 个开放端口全部发 HTTP 请求——那会变成对内网的小型 DoS；
//   3. 已知主机降频、失败退避、时间窗口，交给 schedule.go 的约束统一控制。
//
// 这条顺序是被现实逼出来的：灯塔（ARL）那套 masscan→nmap→爬虫 的价值不在工具本身，
// 而在于"廉价的先做、昂贵的后做、只对活的东西花代价"。StarMap 在这里自持实现，
// 不依赖 masscan/nmap，才能在内网机器上装不上工具时依然有主动发现能力。

// portPlanFor 端口档位解析（可替换，便于测试固定端口集）。
var portPlanFor = PortPlan

// ErrNoTargets 没有可扫描的目标。
var ErrNoTargets = errors.New("没有可扫描的目标")

// DiscoverOptions 一次主动发现的参数。
type DiscoverOptions struct {
	Profile             string             // 端口档位：quick / standard / full
	HostConcurrency     int                // 同时扫描的主机数（默认 4）
	Scan                ScanOptions        // 单主机端口扫描参数
	Fingerprint         FingerprintOptions // 指纹参数
	MaxFingerprintPorts int                // 单主机最多做几个端口的指纹（默认 32）
	SkipFingerprint     bool               // 只扫端口不认服务（适合超大网段摸底）
	// Ports 显式端口列表：非空时**优先于** Profile，用于"只关心这几个端口"的场景
	// （例如只盯 445/3389 查横向移动，或复扫上一轮发现过的端口）。
	Ports      []int
	Known      func(ip string) bool // 已知主机判定：命中则降为 quick 档
	Window     *Window              // 时间窗口：不在窗口内直接拒绝执行
	OnProgress func(Progress)       // 进度回调（必须轻量，别在里面做 IO）
}

// DefaultDiscoverOptions 默认参数。
func DefaultDiscoverOptions() DiscoverOptions {
	return DiscoverOptions{
		Profile:             ProfileStandard,
		HostConcurrency:     4,
		Scan:                DefaultScanOptions(),
		Fingerprint:         DefaultFingerprintOptions(),
		MaxFingerprintPorts: 32,
	}
}

func (o DiscoverOptions) normalize() DiscoverOptions {
	if o.Profile == "" {
		o.Profile = ProfileStandard
	}
	if o.HostConcurrency <= 0 {
		o.HostConcurrency = 4
	}
	if o.HostConcurrency > 64 {
		o.HostConcurrency = 64
	}
	if o.MaxFingerprintPorts <= 0 {
		o.MaxFingerprintPorts = 32
	}
	if o.MaxFingerprintPorts > 256 {
		o.MaxFingerprintPorts = 256
	}
	o.Scan = o.Scan.normalize()
	o.Fingerprint = o.Fingerprint.normalize()
	return o
}

// Progress 进度快照。
type Progress struct {
	Phase        string `json:"phase"` // scan / fingerprint
	Done         int    `json:"done"`
	Total        int    `json:"total"`
	IP           string `json:"ip"`
	Alive        int    `json:"alive"`
	OpenPorts    int    `json:"open_ports"`
	Fingerprints int    `json:"fingerprints"`
}

// HostResult 单主机发现结果。
type HostResult struct {
	IP           string        `json:"ip"`
	Alive        bool          `json:"alive"`
	Profile      string        `json:"profile"` // 实际使用的档位说明（可能因降频而不同）
	Ports        []OpenPort    `json:"ports,omitempty"`
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`
	Scanned      int           `json:"scanned"`
	Elapsed      string        `json:"elapsed"`
	Error        string        `json:"error,omitempty"`
}

// DiscoverResult 一轮主动发现的汇总。
type DiscoverResult struct {
	StartedAt    time.Time    `json:"started_at"`
	Duration     string       `json:"duration"`
	Profile      string       `json:"profile"`
	Total        int          `json:"total"`
	Alive        int          `json:"alive"`
	OpenPorts    int          `json:"open_ports"`
	Fingerprints int          `json:"fingerprints"`
	Hosts        []HostResult `json:"hosts"`
}

// Discover 对一批主机做"端口扫描 + 服务指纹"。
// 单主机失败（不可达、超时）只写进该主机的 Error，不影响整轮结果。
func (s *Scanner) Discover(ctx context.Context, hosts []string, opt DiscoverOptions) (*DiscoverResult, error) {
	opt = opt.normalize()
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}
	if opt.Window != nil && !opt.Window.Contains(s.NowFunc()) {
		return nil, ErrOutsideWindow
	}

	var ports []int
	var label string
	var err error
	if len(opt.Ports) > 0 {
		ports = dedupSorted(append([]int(nil), opt.Ports...))
		if len(ports) == 0 {
			return nil, errors.New("显式端口列表为空或全部非法（需 1-65535）")
		}
		label = fmt.Sprintf("自定义端口（%d 个）", len(ports))
	} else {
		ports, label, err = portPlanFor(opt.Profile)
		if err != nil {
			return nil, err
		}
	}
	// 已知主机降频用的廉价端口集：只算一次，避免每台主机重复构造
	var quickPorts []int
	quickLabel := ""
	if opt.Known != nil {
		if qp, ql, qerr := portPlanFor(ProfileQuick); qerr == nil {
			quickPorts, quickLabel = qp, ql+"（已知主机降频）"
		}
	}

	start := s.NowFunc()
	res := &DiscoverResult{StartedAt: start, Profile: label, Total: len(hosts), Hosts: make([]HostResult, len(hosts))}

	sem := make(chan struct{}, opt.HostConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done, alive, openPorts, fps := 0, 0, 0, 0

	for i, ip := range hosts {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				res.Hosts[i] = HostResult{IP: ip, Error: ctx.Err().Error()}
				return
			}
			if ctx.Err() != nil {
				res.Hosts[i] = HostResult{IP: ip, Error: ctx.Err().Error()}
				return
			}

			hostPorts, hostLabel := ports, label
			if opt.Known != nil && len(quickPorts) > 0 && opt.Known(ip) {
				hostPorts, hostLabel = quickPorts, quickLabel
			}
			hr := s.discoverHost(ctx, ip, hostPorts, hostLabel, opt)
			res.Hosts[i] = hr

			mu.Lock()
			done++
			nAlive, nPorts, nFp, nTotal := alive, openPorts, fps, done
			if hr.Alive {
				alive++
				nAlive++
			}
			openPorts += len(hr.Ports)
			nPorts += len(hr.Ports)
			fps += len(hr.Fingerprints)
			nFp += len(hr.Fingerprints)
			mu.Unlock()

			if opt.OnProgress != nil {
				opt.OnProgress(Progress{
					Phase: "scan", Done: nTotal, Total: len(hosts), IP: ip,
					Alive: nAlive, OpenPorts: nPorts, Fingerprints: nFp,
				})
			}
		}(i, ip)
	}
	wg.Wait()

	res.Duration = s.nowSince(start).String()
	res.Alive = alive
	res.OpenPorts = openPorts
	res.Fingerprints = fps
	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// DiscoverCIDR 对网段做主动发现（/16 以内，超过 4096 个地址直接拒绝）。
func (s *Scanner) DiscoverCIDR(ctx context.Context, cidr string, opt DiscoverOptions) (*DiscoverResult, error) {
	ips, err := expandTarget(cidr, 4096)
	if err != nil {
		return nil, err
	}
	return s.Discover(ctx, ips, opt)
}

// discoverHost 单主机：扫描 → 选端口 → 指纹。
func (s *Scanner) discoverHost(ctx context.Context, ip string, ports []int, label string, opt DiscoverOptions) HostResult {
	t0 := s.NowFunc()
	hr := HostResult{IP: ip, Profile: label, Scanned: len(ports)}

	scanRes, err := s.ScanTCP(ctx, ip, ports, opt.Scan)
	if scanRes != nil {
		hr.Ports = scanRes.Ports
		hr.Scanned = scanRes.Scanned
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		hr.Error = err.Error()
	}
	hr.Alive = len(hr.Ports) > 0

	if hr.Alive && !opt.SkipFingerprint {
		targets := selectFingerprintPorts(hr.Ports, opt.MaxFingerprintPorts)
		hr.Fingerprints = s.fingerprintHost(ctx, ip, targets, opt)
	}
	hr.Elapsed = s.nowSince(t0).String()
	return hr
}

// fingerprintHost 对选定的少量端口做指纹（4 路并发：指纹多是"握手 + 一次 GET"，
// 并发再高只会让对端设备的管理面卡顿，收益很小）。
func (s *Scanner) fingerprintHost(ctx context.Context, ip string, ports []int, opt DiscoverOptions) []Fingerprint {
	if len(ports) == 0 {
		return nil
	}
	out := make([]Fingerprint, 0, len(ports))
	var mu sync.Mutex
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			fp, err := s.Fingerprint(ctx, ip, port, opt.Fingerprint)
			if err != nil || fp == nil {
				return
			}
			mu.Lock()
			out = append(out, *fp)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// selectFingerprintPorts 从开放端口里挑"最值得认身份"的若干个。
//
// 优先级不是拍脑袋：TLS 证书能直接给出域名（把 IP 还原成业务系统），
// Web 端口能给出标题与产品，已知服务端口能给 banner，其余端口做指纹基本是浪费。
func selectFingerprintPorts(ports []OpenPort, max int) []int {
	type cand struct {
		port  int
		score int
	}
	cands := make([]cand, 0, len(ports))
	for _, p := range ports {
		score := 10
		switch {
		case tlsPorts[p.Port]:
			score = 100
		case webPorts[p.Port]:
			score = 90
		case bannerPorts[p.Port]:
			score = 50
		}
		cands = append(cands, cand{port: p.Port, score: score})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].port < cands[j].port
	})
	if max > 0 && len(cands) > max {
		cands = cands[:max]
	}
	out := make([]int, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.port)
	}
	sort.Ints(out) // 结果按端口升序，便于稳定对比与入库
	return out
}

// ExpandTargets 把一批 IP / CIDR 展开成主机列表（去重，总量受 limit 约束）。
// limit 是"总主机数"上限：多个网段累加后仍不允许超过它，
// 否则一次误填 "10.0.0.0/8,172.16.0.0/12" 就能把扫描面放大到不可收拾。
func ExpandTargets(targets []string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 4096
	}
	seen := map[string]bool{}
	out := make([]string, 0, 64)
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ips, err := expandTarget(t, limit)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t, err)
		}
		for _, ip := range ips {
			if seen[ip] {
				continue
			}
			if len(out) >= limit {
				return out, fmt.Errorf("目标主机总数超过上限 %d，请缩小扫描范围", limit)
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoTargets
	}
	return out, nil
}
