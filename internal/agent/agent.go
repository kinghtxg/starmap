// Package agent 独立探针：本地采集 → 聚合会话 → 上报 StarMap 服务端。
//
// 设计上的三个决定：
//
//  1. **采集后端可插拔，且一律不依赖 CGO**。原因很现实：目标机器上往往没有 gcc，
//     也装不了 Wireshark。探针如果需要一个编译工具链才能构建，它在多数内网里就
//     跑不起来。file / exec / afpacket / npcap 四个后端全都不碰 CGO，
//     所以 `go build ./cmd/starmap-probe` 直接出一个能跑的单文件。
//
//  2. **会话聚合复用 internal/parser.Aggregator**，不自己写一套粘包逻辑。
//     两套聚合逻辑必然分叉，最后表现为"探针算出的会话和服务端算出的不一样"——
//     这种 bug 没有报错、没有日志，只能靠人肉对比数字才能发现。
//
//  3. **上报 flows 而不是 packets**。一个会话只发一条记录，带宽和 CPU 都省一个量级。
//     服务端 probeFlow 已支持 SNI / JA3 / JA4 / XFF 贯通，不会因为聚合而丢指纹。
package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"starmap/internal/parser"
)

// Frame 一帧链路层数据及其被抓到的时刻。
// Data 必须是独立分配的：下游解码会持有它直到会话结束。
type Frame struct {
	Data []byte
	TS   time.Time
}

// Source 采集后端。
type Source interface {
	// Name 用于日志，形如 "file:/tmp/a.pcap"。
	Name() string
	// Frames 返回帧通道；后端结束时必须关闭它。
	Frames() <-chan Frame
	// LinkType 链路层类型（以太网 / Linux cooked 等）。
	LinkType() layers.LinkType
	// Close 停止采集。可重复调用。
	Close() error
}

// ErrNoSource 没有可用的采集后端。
var ErrNoSource = errors.New("没有可用的采集源")

// Config 探针运行时配置。
type Config struct {
	// Server 服务端地址，如 http://192.168.31.100:8080。
	Server string
	// Token 对应服务端 probe_token；服务端未配置时留空。
	Token string
	// ProbeID 探针标识，同一部署内唯一。默认取主机名。
	ProbeID string
	// Name 人读名称。
	Name string
	// Location 探针位置（V1.3 起用于拓扑按位置归纳，务必填得有辨识度）。
	Location string

	// Interval 聚合刷新间隔：会话增量多久上报一次。
	Interval time.Duration
	// Report 运行统计的输出间隔。默认 60s；排查"探针在跑但页面没数据"时
	// 调到 5s 就能立刻看出是没抓到帧、还是抓到了没聚出会话、还是上报失败。
	Report time.Duration
	// Batch 单次 POST 的最大会话数。
	Batch int
	// Buffer 离线缓冲上限（会话条数）。服务端不可达时先攒着，超了丢最旧的。
	Buffer int
	// Once 源读完后立即 flush 并退出（回放 pcap 时用）。
	Once bool

	// LongConnSeconds / HeartbeatMaxBytes 与服务端同名配置项保持一致，
	// 否则探针判定的"长连接心跳"和服务端规则会对不上。
	LongConnSeconds   int64
	HeartbeatMaxBytes int

	// DryRun 不上报，只把会话数打到日志里（排查采集是否正常）。
	DryRun bool

	// Logger 为空则用 slog.Default()。
	Logger *slog.Logger
}

func (c *Config) normalize() {
	if c.Server == "" {
		c.Server = "http://127.0.0.1:8080"
	}
	if c.ProbeID == "" {
		c.ProbeID = "probe"
	}
	if c.Interval <= 0 {
		c.Interval = 10 * time.Second
	}
	if c.Report <= 0 {
		c.Report = 60 * time.Second
	}
	if c.Batch <= 0 {
		c.Batch = 500
	}
	if c.Buffer <= 0 {
		c.Buffer = 20000
	}
	if c.LongConnSeconds <= 0 {
		c.LongConnSeconds = 3600
	}
	if c.HeartbeatMaxBytes <= 0 {
		c.HeartbeatMaxBytes = 64
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Stats 运行统计，供日志与退出时汇报。
type Stats struct {
	Frames   int64
	Packets  int64 // 解析出 IP/TCP/UDP 的报文数
	Sessions int64 // 累计上报的会话条数
	PushFail int64
	Dropped  int64
}

// Agent 探针主体。
type Agent struct {
	cfg Config
	src Source
	agg *parser.Aggregator
	snd *Sender
	log *slog.Logger
	st  Stats
}

// Run 阻塞运行直到 ctx 结束（Once 模式下源读完即返回）。
func Run(ctx context.Context, cfg Config, src Source) error {
	cfg.normalize()
	if src == nil {
		return ErrNoSource
	}
	a := &Agent{
		cfg: cfg,
		src: src,
		agg: parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes),
		log: cfg.Logger,
	}
	if !cfg.DryRun {
		a.snd = NewSender(SenderConfig{
			Server:   cfg.Server,
			Token:    cfg.Token,
			ProbeID:  cfg.ProbeID,
			Name:     cfg.Name,
			Location: cfg.Location,
			Batch:    cfg.Batch,
			Buffer:   cfg.Buffer,
			Logger:   cfg.Logger,
		})
	}
	return a.run(ctx)
}

func (a *Agent) run(ctx context.Context) error {
	a.log.Info("探针启动",
		"source", a.src.Name(),
		"probe_id", a.cfg.ProbeID,
		"location", a.cfg.Location,
		"server", a.cfg.Server,
		"interval", a.cfg.Interval.String(),
		"report", a.cfg.Report.String(),
		"dry_run", a.cfg.DryRun,
	)

	if a.snd != nil {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go a.snd.Run(sctx)
	}

	readerDone := make(chan struct{})
	go a.readLoop(readerDone)

	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()

	report := time.NewTicker(a.cfg.Report)
	defer report.Stop()

	for {
		select {
		case <-ctx.Done():
			a.teardown(readerDone)
			a.log.Info("探针退出", a.statArgs()...)
			return nil
		case <-readerDone:
			// 源结束（文件读完 / 采集进程退出）：把余量冲出去。
			a.teardown(readerDone)
			if a.cfg.Once {
				a.log.Info("回放结束", a.statArgs()...)
			} else {
				a.log.Warn("采集源已结束，探针退出", a.statArgs()...)
			}
			return nil
		case <-ticker.C:
			a.flush()
		case <-report.C:
			a.log.Info("探针运行中", a.statArgs()...)
		}
	}
}

// teardown 收尾。顺序是有讲究的，反过来会丢一段数据：
//
//	先停采集 → 等读协程退出 → 冲会话增量 → 冲上报队列
//
// 如果先 flush 再停采集，flush 和 src.Close 之间读协程还在往聚合器里灌，
// 这批会话既不在这次 flush 里，也赶不上后面的队列冲刷，就静默丢了。
func (a *Agent) teardown(readerDone <-chan struct{}) {
	_ = a.src.Close()
	select {
	case <-readerDone:
	case <-time.After(3 * time.Second):
		// 采集后端卡住也不能拖着不让进程退出——运维 systemctl stop 等不了。
		a.log.Warn("采集协程未在 3s 内退出，继续收尾")
	}
	a.flush()
	if a.snd != nil {
		a.snd.Close()
	}
}

// readLoop 把帧解码成 PacketInfo 并喂给聚合器。
func (a *Agent) readLoop(done chan<- struct{}) {
	defer close(done)
	lt := a.src.LinkType()
	for f := range a.src.Frames() {
		atomic.AddInt64(&a.st.Frames, 1)
		// Default 会复制各层数据。NoCopy 更快，但会让每个会话都持有整帧引用，
		// 在长时间运行的探针上就是内存缓慢上涨——宁可多复制一次。
		pkt := gopacket.NewPacket(f.Data, lt, gopacket.Default)
		info := parser.ParsePacket(pkt)
		if info == nil {
			continue
		}
		if info.Timestamp.IsZero() {
			info.Timestamp = f.TS
		}
		if info.Location == "" {
			info.Location = a.cfg.Location
		}
		a.agg.Ingest(info)
		atomic.AddInt64(&a.st.Packets, 1)
	}
}

// flush 取走本轮的会话增量并交给发送队列。
func (a *Agent) flush() {
	res := a.agg.Drain(time.Now())
	if len(res.Entries) == 0 {
		return
	}
	flows := MapSessions(res.Sessions())
	if len(flows) == 0 {
		return
	}
	atomic.AddInt64(&a.st.Sessions, int64(len(flows)))
	if a.snd == nil {
		a.log.Debug("dry-run 会话增量", "flows", len(flows), "active", res.Active)
		return
	}
	a.snd.Push(flows)
}

func (a *Agent) statArgs() []any {
	return []any{
		"frames", atomic.LoadInt64(&a.st.Frames),
		"packets", atomic.LoadInt64(&a.st.Packets),
		"sessions_sent", atomic.LoadInt64(&a.st.Sessions),
		"active", a.agg.Stats().Active,
	}
}
