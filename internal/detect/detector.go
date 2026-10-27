// Package detect 检测调度器 + 规则实现（SPEC §5）。
// 所有规则只打标签（生成 pending 风险事件），不做定性/告警外发/解密。
// 事件去重按 §10.5；白名单抑制见 whitelist.go。
package detect

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// DedupWindow 事件去重窗口（SPEC §10.5）
const DedupWindow = 24 * time.Hour

// Detector 检测调度器：周期性扫描会话 + 拓扑，产出风险事件。
type Detector struct {
	Store  *store.Store
	Engine *topology.Engine
	Cfg    model.SystemConfig

	// SessionsFunc 提供当前会话快照（通常接 parser.Aggregator.Finalize）
	SessionsFunc func() []model.Session

	// Interval 评估周期；默认 30s
	Interval time.Duration
	// LearningPeriod 未知出口基线学习期（§10.4 默认 10min）
	LearningPeriod time.Duration
	// NowFunc 可注入时钟（测试用）
	NowFunc func() time.Time

	// mu 保护 started / Cfg / egress.baseline。
	// P0-1 修复：HTTP 上传同步评估（evaluateAsync）与 Run 的 30s 周期评估
	// 会并发进入 evalUnknownEgress，对 egress.baseline 裸 map 并发写，触发
	// Go runtime "fatal error: concurrent map writes"。fatal error 不经过
	// panic()，因此 gin.Recovery() 无法拦截，进程直接退出。
	mu      sync.Mutex
	started time.Time
	egress  *egressTracker
	stop    chan struct{}
}

// New 创建检测调度器。
func New(st *store.Store, eng *topology.Engine, cfg model.SystemConfig) *Detector {
	d := &Detector{
		Store:          st,
		Engine:         eng,
		Cfg:            cfg,
		Interval:       30 * time.Second,
		LearningPeriod: 10 * time.Minute,
		NowFunc:        time.Now,
		egress:         newEgressTracker(),
		stop:           make(chan struct{}),
	}
	return d
}

// UpdateConfig 热更新配置。
func (d *Detector) UpdateConfig(cfg model.SystemConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Cfg = cfg
}

// Run 启动周期性评估循环（阻塞，ctx 取消退出）。
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case <-t.C:
			if _, err := d.Evaluate(); err != nil {
				log.Printf("[detect] 评估失败: %v", err)
			}
		}
	}
}

// Stop 停止调度器。
func (d *Detector) Stop() { close(d.stop) }

// Evaluate 执行一轮全部规则评估，返回新建的事件（去重命中的仅更新证据）。
func (d *Detector) Evaluate() ([]*model.RiskEvent, error) {
	// P0-1：整轮评估串行化，覆盖 started / Cfg / egress.baseline 的共享写。
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.NowFunc()
	if d.started.IsZero() {
		d.started = now // 学习期自首次评估起算
	}
	sessions := []model.Session{}
	if d.SessionsFunc != nil {
		sessions = d.SessionsFunc()
	}
	rc := &ruleContext{
		d:        d,
		sessions: sessions,
		now:      now,
	}

	var candidates []model.RiskEvent
	candidates = append(candidates, evalFRP(rc)...)
	candidates = append(candidates, evalClash(rc)...)
	candidates = append(candidates, evalReverseProxy(rc)...)
	candidates = append(candidates, evalUnknownEgress(rc)...)
	candidates = append(candidates, evalMultiNet(rc)...)
	candidates = append(candidates, evalXFFSpoof(rc)...)

	whitelist, err := d.Store.ListWhitelist()
	if err != nil {
		return nil, err
	}

	var created []*model.RiskEvent
	for i := range candidates {
		ev := &candidates[i]
		node := d.Engine.GetNode(ev.NodeID)

		// 白名单抑制：命中则不产生事件
		if MatchAnyWhitelist(whitelist, ev, node) {
			continue
		}

		// §10.5 去重：同 (type,node_id) 且 24h 内已有 pending/confirmed → 更新证据
		if existing := d.findRecent(ev.Type, ev.NodeID, now); existing != nil {
			for k, v := range ev.Evidence {
				existing.Evidence[k] = v
			}
			if err := d.Store.UpdateEventEvidence(existing.ID, existing.Evidence); err != nil {
				return created, err
			}
			continue
		}

		ev.Status = model.EventStatusPending
		ev.CreatedAt = now
		// 记下稳定的节点身份：只存自增 node_id，节点一旦离线被清理再重建，
		// 老事件就指向了一个不存在的行（界面上"关联节点"退化成裸数字）。
		if node != nil {
			ev.NodeKey = node.NodeKey
		}
		id, err := d.Store.CreateEvent(ev)
		if err != nil {
			return created, err
		}
		ev.ID = id
		// 事件 Level → 节点 RiskLevel 联动（§10.6）+ 只打标签
		d.Engine.SetNodeRisk(ev.NodeID, ev.Level)
		d.Engine.AddNodeLabel(ev.NodeID, ev.Type)
		created = append(created, ev)
	}
	return created, nil
}

// findRecent 查找 24h 去重窗口内同类型同节点的 pending/confirmed 事件。
func (d *Detector) findRecent(evType string, nodeID int64, now time.Time) *model.RiskEvent {
	for _, st := range []string{model.EventStatusPending, model.EventStatusConfirmed} {
		evs, err := d.Store.ListEvents(st, evType)
		if err != nil {
			return nil
		}
		for i := range evs {
			if evs[i].NodeID == nodeID && now.Sub(evs[i].CreatedAt) < DedupWindow {
				return &evs[i]
			}
		}
	}
	return nil
}

// ruleContext 规则评估上下文
type ruleContext struct {
	d        *Detector
	sessions []model.Session
	now      time.Time
}

// internalNodeOf 返回会话内网侧节点（优先源侧）。
func (rc *ruleContext) internalNodeOf(s *model.Session) *model.Node {
	if topology.IsPrivate(s.FiveTuple.SrcIP) {
		return rc.d.Engine.NodeByIP(s.FiveTuple.SrcIP)
	}
	if topology.IsPrivate(s.FiveTuple.DstIP) {
		return rc.d.Engine.NodeByIP(s.FiveTuple.DstIP)
	}
	return nil
}

// publicPeerOf 返回会话的公网侧 IP（无则空串）。
func publicPeerOf(s *model.Session) string {
	srcPriv := topology.IsPrivate(s.FiveTuple.SrcIP)
	dstPriv := topology.IsPrivate(s.FiveTuple.DstIP)
	switch {
	case srcPriv && !dstPriv:
		return s.FiveTuple.DstIP
	case dstPriv && !srcPriv:
		return s.FiveTuple.SrcIP
	}
	return ""
}

// sessionDuration 会话时长（按报文时间戳，§10.2）。
func sessionDuration(s *model.Session) time.Duration {
	return s.LastSeen.Sub(s.FirstSeen)
}

func evTitle(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func nodeIDStr(id int64) string { return strconv.FormatInt(id, 10) }
