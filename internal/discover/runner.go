// Package discover 主动发现的执行器：把"配置 → 扫描 → 指纹 → 落库 + 喂拓扑"这条链路
// 收在一处，供「手动触发（API）」与「周期任务（后台）」共用。
//
// 为什么单独成包而不是写在 api 里：周期任务需要在没有 HTTP 请求的时候跑，
// 若逻辑挂在 api.Server 上，后台任务就只能依赖一个 HTTP handler 的实例。
// 更要紧的是——两条路径各写一份必然跑偏（一条修了限速、另一条忘了），
// 这类"手动能扫、定时不扫"的幽灵 bug 在内网运维里极难排查。
package discover

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"starmap/internal/logging"
	"starmap/internal/model"
	"starmap/internal/probe"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// MaxHosts 单轮最多扫描的主机数（≈32 个 /24）。
// 上限的存在不是为了性能，而是防手误：一次填进 /8 会把整个内网打成风暴。
const MaxHosts = 8192

// Runner 主动发现执行器。
type Runner struct {
	Store   *store.Store
	Engine  *topology.Engine
	Scanner *probe.Scanner
	// Cfg 返回当前配置（配置热更新后立即读到新值，不需要重启）。
	Cfg func() model.SystemConfig

	// tick 检查间隔（默认 1 分钟；测试注入短间隔以便快速验证循环逻辑）。
	tick time.Duration
}

func (r *Runner) tickInterval() time.Duration {
	if r.tick > 0 {
		return r.tick
	}
	return time.Minute
}

// Options 把系统配置翻译成发现参数。
func (r *Runner) Options(profile string, fingerprint *bool) probe.DiscoverOptions {
	cfg := r.Cfg()
	opt := probe.DefaultDiscoverOptions()
	if profile == "" {
		profile = cfg.DiscoverProfile
	}
	opt.Profile = profile
	opt.Scan = probe.ScanOptions{
		Concurrency: cfg.DiscoverConcurrency,
		Timeout:     time.Duration(cfg.DiscoverTimeoutMS) * time.Millisecond,
		RatePPS:     cfg.DiscoverRatePPS,
	}
	if cfg.DiscoverMaxFP > 0 {
		opt.MaxFingerprintPorts = cfg.DiscoverMaxFP
	}
	want := cfg.DiscoverFingerprint
	if fingerprint != nil {
		want = *fingerprint
	}
	opt.SkipFingerprint = !want
	// 已知主机降频：已在拓扑里的 IP 只扫高价值端口，把速率预算留给没见过的地址——
	// 账外资产只可能出现在"从没见过"的地方。
	if r.Engine != nil {
		opt.Known = func(ip string) bool { return r.Engine.NodeByIP(ip) != nil }
	}
	if w, err := probe.ParseWindow(cfg.DiscoverWindow); err == nil {
		opt.Window = &w
	}
	return opt
}

// Run 执行一轮发现并落库；onProgress 可为 nil。
func (r *Runner) Run(ctx context.Context, hosts []string, opt probe.DiscoverOptions, onProgress func(probe.Progress)) (*probe.DiscoverResult, error) {
	if r.Scanner == nil {
		return nil, errors.New("主动探测器未初始化")
	}
	if onProgress != nil {
		opt.OnProgress = onProgress
	}
	res, err := r.Scanner.Discover(ctx, hosts, opt)
	if res != nil && r.Store != nil {
		records := r.portRecords(res, time.Now())
		if len(records) > 0 {
			if uerr := r.Store.UpsertPorts(records); uerr != nil && err == nil {
				err = uerr
			}
		}
	}
	return res, err
}

// portRecords 发现结果 → 端口记录（含指纹），并让活跃主机进入拓扑。
func (r *Runner) portRecords(res *probe.DiscoverResult, now time.Time) []model.PortRecord {
	records := make([]model.PortRecord, 0, res.OpenPorts)
	for i := range res.Hosts {
		h := &res.Hosts[i]
		if !h.Alive {
			continue
		}
		nodeKey := ""
		if r.Engine != nil {
			// 顺序不能反：第一次发现的主机在拓扑里还不存在，
			// 必须先 ObserveHost 建节点，再取 node_key——
			// 否则首轮发现的端口全部挂不上主机，资产详情里看不到端口。
			r.Engine.ObserveHost(h.IP, "", now)
			if n := r.Engine.NodeByIP(h.IP); n != nil {
				nodeKey = n.NodeKey
			}
		}
		fps := make(map[int]probe.Fingerprint, len(h.Fingerprints))
		for _, fp := range h.Fingerprints {
			fps[fp.Port] = fp
		}
		for _, p := range h.Ports {
			rec := model.PortRecord{
				NodeKey: nodeKey, IP: h.IP, Port: p.Port, Proto: "tcp",
				State: "open", Source: model.PortSourceProbe,
				FirstSeen: now, LastSeen: now,
			}
			if fp, ok := fps[p.Port]; ok {
				rec.Service = fp.Service
				rec.Product = fp.Product
				rec.Version = fp.Version
				rec.Title = fp.Title
				rec.Banner = fp.Banner
				rec.TLSCN = fp.TLSCN
				rec.TLSNames = fp.TLSNames
				rec.Favicon = fp.Favicon
			}
			records = append(records, rec)
		}
	}
	return records
}

// Loop 周期任务：按 discover_sec 间隔对 discover_cidrs 做主动发现。
//
// 三重约束缺一不可（也是这套东西能挂在生产内网的前提）：
//   - 时间窗口：窗口外直接跳过，不在业务高峰发包；
//   - 失败退避：某网段连续失败就指数拉长重试间隔，别把速率预算耗在已经下线的网段上；
//   - 单轮上限：网段数 × 每网段主机数都受 MaxHosts 约束，防手误。
//
// 采用"每分钟检查一次、到点才跑"而不是固定间隔 Ticker：
// 周期、网段、开关都可能在界面上被改，固定 Ticker 只有重启才生效——
// 那正是本项目最忌讳的"开关看着改了其实没变"。
func (r *Runner) Loop(ctx context.Context) {
	backoff := probe.NewBackoff(5*time.Minute, 6*time.Hour)
	t := time.NewTicker(r.tickInterval())
	defer t.Stop()
	var last time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := r.Cfg()
		if !cur.DiscoverEnabled || cur.DiscoverSec <= 0 || len(cur.DiscoverCIDRs) == 0 {
			continue
		}
		now := time.Now()
		interval := time.Duration(cur.DiscoverSec) * time.Second
		if !last.IsZero() && now.Sub(last) < interval {
			continue
		}
		w, err := probe.ParseWindow(cur.DiscoverWindow)
		if err != nil {
			slog.Warn("主动发现时间窗口非法，本轮跳过", "window", cur.DiscoverWindow, logging.Err(err))
			last = now
			continue
		}
		if !w.Contains(now) {
			slog.Debug("不在扫描时间窗口内，本轮跳过", "window", w.String())
			continue // 不更新 last：窗口一开就立刻补跑，而不是再等一个完整周期
		}
		last = now

		for _, cidr := range cur.DiscoverCIDRs {
			if ctx.Err() != nil {
				return
			}
			if !backoff.Due(cidr, time.Now()) {
				slog.Debug("网段处于失败退避期，跳过",
					"cidr", cidr, "retry_at", backoff.NextRetry(cidr).Format(time.RFC3339))
				continue
			}
			hosts, herr := probe.ExpandTargets([]string{cidr}, MaxHosts)
			if herr != nil {
				// 配置错误（如写成 /8）不该静默退避，直接报出来让人改
				slog.Error("主动发现目标非法，跳过该网段", "cidr", cidr, logging.Err(herr))
				continue
			}
			start := time.Now()
			res, rerr := r.Run(ctx, hosts, r.Options(cur.DiscoverProfile, nil), nil)
			if rerr != nil {
				d := backoff.Fail(cidr, time.Now())
				slog.Warn("主动发现失败，进入退避", "cidr", cidr, "retry_in", d.String(),
					"fails", backoff.Fails(cidr), logging.Err(rerr))
				continue
			}
			backoff.Succeed(cidr)
			if res != nil {
				slog.Info("主动发现完成",
					"cidr", cidr, "hosts", res.Total, "alive", res.Alive,
					"open_ports", res.OpenPorts, "fingerprints", res.Fingerprints,
					"elapsed", time.Since(start).Round(time.Second).String())
			}
		}
	}
}

func orAllDay(w string) string {
	if w == "" {
		return "全天"
	}
	return w
}

// SortHostsByIP 按 IP 数值序排序（字符串排序会把 10.0.0.10 排到 10.0.0.9 前面）。
func SortHostsByIP(hosts []probe.HostResult) {
	sort.SliceStable(hosts, func(i, j int) bool { return ipLess(hosts[i].IP, hosts[j].IP) })
}

func ipLess(a, b string) bool {
	pa, pb := parseIPv4(a), parseIPv4(b)
	if pa != nil && pb != nil {
		for i := 0; i < 4; i++ {
			if pa[i] != pb[i] {
				return pa[i] < pb[i]
			}
		}
		return false
	}
	return a < b
}

func parseIPv4(s string) []int {
	// 只处理点分十进制：内网扫描目标就是 IPv4，不为此引入 net 的解析开销
	out := make([]int, 0, 4)
	cur, has := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if !has || len(out) == 4 {
				return nil
			}
			out = append(out, cur)
			cur, has = 0, false
			continue
		}
		if c < '0' || c > '9' {
			return nil
		}
		cur = cur*10 + int(c-'0')
		has = true
		if cur > 255 {
			return nil
		}
	}
	if !has || len(out) != 3 {
		return nil
	}
	return append(out, cur)
}
