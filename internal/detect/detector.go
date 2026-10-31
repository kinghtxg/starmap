// Package detect 检测调度器 + 规则实现（SPEC §5）。
// 所有规则只打标签（生成 pending 风险事件），不做定性/告警外发/解密。
// 事件去重按 §10.5；白名单抑制见 whitelist.go。
package detect

import (
	"context"
	"log"
	"net"
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
	// kick 触发一次「尽快评估」（缓冲 1，天然合并突发上报）。
	// 上报路径不再同步跑全量评估——那样单次上报的耗时等于一轮全量检测，
	// 网络一大就整条数据接入链路被拖垮。
	kick chan struct{}

	// minKickInterval 两次触发评估之间的最小间隔：上报是持续的，
	// 没有下限就会变成「用上报频率跑全量评估」。
	minKickInterval time.Duration
}

// DefaultMinKickInterval 触发性评估的最小间隔。
//
// 取值要同时满足两头：
//   - 别太密：一轮评估的成本随会话/节点/事件数线性增长（实测 2 万主机约 360ms），
//     2 秒一轮等于让评估器常驻满负荷，把 HTTP 接口一起拖慢；
//   - 别太稀：这是被动分析产品，事件晚 5 秒出现没有任何影响，晚 30 秒就会
//     让人觉得"导入了 pcap 却没反应"。
const DefaultMinKickInterval = 5 * time.Second

// New 创建检测调度器。
func New(st *store.Store, eng *topology.Engine, cfg model.SystemConfig) *Detector {
	d := &Detector{
		Store:           st,
		Engine:          eng,
		Cfg:             cfg,
		Interval:        30 * time.Second,
		LearningPeriod:  10 * time.Minute,
		NowFunc:         time.Now,
		egress:          newEgressTracker(),
		stop:            make(chan struct{}),
		kick:            make(chan struct{}, 1),
		minKickInterval: DefaultMinKickInterval,
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
//
// 除固定周期外，还响应 Kick()：数据接入方在写入新会话后踢一脚，
// 新事件因此能在一两秒内出现，而不是等到下一个 30s 周期。
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	lastEval := time.Time{}
	evaluate := func() {
		lastEval = time.Now()
		if _, err := d.Evaluate(); err != nil {
			log.Printf("[detect] 评估失败: %v", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case <-t.C:
			evaluate()
		case <-d.kick:
			// 合并突发：离上次评估太近就跳过，剩下的等周期 ticker 兜底。
			if gap := d.minKickInterval; gap > 0 && !lastEval.IsZero() && time.Since(lastEval) < gap {
				continue
			}
			evaluate()
		}
	}
}

// Kick 请求尽快评估一次（非阻塞，可安全地在请求路径调用）。
// 已有未处理的触发时直接丢弃——评估是全量的，排两次队没有意义。
func (d *Detector) Kick() {
	if d == nil {
		return
	}
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// Stop 停止调度器。
func (d *Detector) Stop() { close(d.stop) }

// Evaluate 执行一轮全部规则评估，返回新建的事件（去重命中的仅更新证据）。
func (d *Detector) Evaluate() ([]*model.RiskEvent, error) {
	// P0-1：整轮评估串行化，覆盖 started / Cfg / egress.baseline 的共享写。
	d.mu.Lock()
	defer d.mu.Unlock()

	started := time.Now()
	now := d.NowFunc()
	if d.started.IsZero() {
		d.started = now // 学习期自首次评估起算
	}
	// 分段计时：评估变慢时最难回答的问题是"这 8 秒花在哪一段"。
	// 抄一份会话、建节点索引、六条规则、读白名单、建去重索引、落库，
	// 每段都单独记时，只在整轮偏慢时输出，正常轮次零开销。
	var seg struct {
		copy, index, rules, wl, dedup, loop, write time.Duration
		ruleCost                                   [6]time.Duration
	}
	mark := func() time.Time { return time.Now() }

	t0 := mark()
	sessions := []model.Session{}
	if d.SessionsFunc != nil {
		sessions = d.SessionsFunc()
	}
	t1 := mark()

	rc := newRuleContext(d, sessions, now)
	t2 := mark()

	var candidates []model.RiskEvent
	rules := [6]func(*ruleContext) []model.RiskEvent{
		evalFRP, evalClash, evalReverseProxy, evalUnknownEgress, evalMultiNet, evalXFFSpoof,
	}
	for i, fn := range rules {
		start := mark()
		candidates = append(candidates, fn(rc)...)
		seg.ruleCost[i] = mark().Sub(start)
	}
	t3 := mark()

	whitelist, err := d.Store.ListWhitelist()
	if err != nil {
		return nil, err
	}
	t4 := mark()

	seg.copy, seg.index, seg.rules, seg.wl = t1.Sub(t0), t2.Sub(t1), t3.Sub(t2), t4.Sub(t3)

	var created []*model.RiskEvent
	// 本轮需要落库的证据变更，统一在末尾一次事务提交。
	var pendingUpdates []evidenceUpdate
	// 本轮新建的事件也攒起来一次事务写入：一条一条 INSERT 是自动提交，
	// 每台新主机就要一次落盘；网络在长，这条路径的写次数是没有上限的。
	var pendingCreates []*model.RiskEvent

	// 单轮评估是有成本的：它整表拷一遍会话、遍历全量节点、还要读一遍历史事件。
	// 网络一大就会出现"每 2 秒跑一轮、每轮跑好几秒"的自激状态，把 CPU 吃满、
	// 拖慢所有 HTTP 接口，而现场只能看到"服务变卡"，看不出是谁在吃。
	// 这里把超时的轮次打出来，让"谁吃满了 CPU"这件事有据可查。
	defer func() {
		if el := time.Since(started); el > time.Second {
			ms := func(d time.Duration) int64 { return d.Milliseconds() }
			log.Printf("[detect] 单轮评估偏慢：%v（会话 %d、节点 %d、候选 %d、新建 %d、证据更新 %d）"+
				" 分段：copy=%dms index=%dms rules=%dms[frp=%d clash=%d rev=%d egress=%d multinet=%d xff=%d] "+
				"wl=%dms dedup=%dms loop=%dms write=%dms",
				el.Round(time.Millisecond), len(sessions), len(rc.nodes), len(candidates), len(created), len(pendingUpdates),
				ms(seg.copy), ms(seg.index), ms(seg.rules),
				ms(seg.ruleCost[0]), ms(seg.ruleCost[1]), ms(seg.ruleCost[2]),
				ms(seg.ruleCost[3]), ms(seg.ruleCost[4]), ms(seg.ruleCost[5]),
				ms(seg.wl), ms(seg.dedup), ms(seg.loop), ms(seg.write))
		}
	}()
	// 本轮需要落库的证据变更，统一在末尾一次事务提交。
	var pendingUpdates []evidenceUpdate
	// 本轮新建的事件也攒起来一次事务写入：一条一条 INSERT 是自动提交，
	// 每台新主机就要一次落盘；网络在长，这条路径的写次数是没有上限的。
	var pendingCreates []*model.RiskEvent
	// 去重索引一轮只建一次：原实现每个候选查两次库，O(候选数 × 历史事件数)。
	dedup := d.buildDedupIndex(now)
	for i := range candidates {
		ev := &candidates[i]
		node := rc.nodeByID(ev.NodeID)

		// 白名单抑制：命中则不产生事件
		if MatchAnyWhitelist(whitelist, ev, node) {
			continue
		}

		// §10.5 去重：同 (type,node_id) 且 24h 内已有 pending/confirmed → 更新证据
		if existing := dedup.find(ev.Type, ev.NodeID); existing != nil {
			// 证据没变就一个字节都别写。
			// 稳态下每轮评估都会重新算出同一批候选，如果无条件 UPDATE，
			// 6 千个事件 × 每 2 秒一轮 = 每秒 3 千次写，SQLite 只有一个写者，
			// 于是整个服务的写路径被自己的评估拖住（实测上报延迟涨到 17 秒）。
			//
			// ID 为 0 说明这条是本轮刚建、还没落库的：证据已经在内存里合并好了，
			// 随创建语句一起写下去即可，不能再排一条 UPDATE（那条会打到 id=0 上）。
			if mergeEvidence(existing.Evidence, ev.Evidence) && existing.ID != 0 {
				pendingUpdates = append(pendingUpdates, evidenceUpdate{id: existing.ID, evidence: existing.Evidence})
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
		// 先入索引占位：同一轮里若还有同 (类型,节点) 的候选，应合并到这条，
		// 而不是再建一条（此时 ev.ID 还是 0，靠上面的判断避免排 UPDATE）。
		dedup[dedupKey{typ: ev.Type, nodeID: ev.NodeID}] = ev
		pendingCreates = append(pendingCreates, ev)
	}

	if len(pendingCreates) > 0 {
		ids, err := d.Store.CreateEvents(pendingCreates)
		if err != nil {
			return created, err
		}
		// 事件 → 节点的风险/标签联动，一次加锁批量应用。
		effects := make([]topology.NodeEffect, 0, len(pendingCreates))
		for i, ev := range pendingCreates {
			ev.ID = ids[i]
			effects = append(effects, topology.NodeEffect{NodeID: ev.NodeID, Level: ev.Level, Label: ev.Type})
			created = append(created, ev)
		}
		d.Engine.ApplyNodeEffects(effects)
	}
	if len(pendingUpdates) > 0 {
		ids := make([]int64, len(pendingUpdates))
		evs := make([]map[string]string, len(pendingUpdates))
		for i := range pendingUpdates {
			ids[i] = pendingUpdates[i].id
			evs[i] = pendingUpdates[i].evidence
		}
		if err := d.Store.UpdateEventEvidenceBatch(ids, evs); err != nil {
			return created, err
		}
	}
	return created, nil
}

// evidenceUpdate 一条待落库的证据变更。
type evidenceUpdate struct {
	id       int64
	evidence map[string]string
}

// mergeEvidence 把新证据并入已有证据，返回是否发生了实际变化。
func mergeEvidence(dst, src map[string]string) bool {
	changed := false
	for k, v := range src {
		if old, ok := dst[k]; ok && old == v {
			continue
		}
		dst[k] = v
		changed = true
	}
	return changed
}

// dedupKey 事件去重键：(类型, 节点)。
type dedupKey struct {
	typ    string
	nodeID int64
}

// dedupIndex 一轮评估内的事件去重索引。
//
// 原来的实现是「每个候选事件都查一次库」：两次 ListEvents 全表读 + 线性扫描。
// 候选数随节点数增长，于是单轮评估是 O(N²) 次行读取——实测 1000 个会话
// 单轮 13 秒、3000 个会话 42 秒，而它又跑在 HTTP 上报路径里，
// 探针上报会随网络规模线性劣化到超时。改成一轮只建一次索引。
type dedupIndex map[dedupKey]*model.RiskEvent

// buildDedupIndex 一次性装载 24h 窗口内的 pending/confirmed 事件。
// 同一 (类型,节点) 有多个历史事件时保留最新的（原实现按 id DESC 排序，
// 取到的也是最新那条，语义保持一致）。
func (d *Detector) buildDedupIndex(now time.Time) dedupIndex {
	idx := make(dedupIndex, 256)
	for _, st := range []string{model.EventStatusPending, model.EventStatusConfirmed} {
		evs, err := d.Store.ListEvents(st, "")
		if err != nil {
			// 查询失败时退化为空索引：宁可多建一条事件，也不要漏报。
			continue
		}
		for i := range evs {
			ev := &evs[i]
			if now.Sub(ev.CreatedAt) >= DedupWindow {
				continue
			}
			k := dedupKey{typ: ev.Type, nodeID: ev.NodeID}
			if old, ok := idx[k]; !ok || ev.ID > old.ID {
				idx[k] = ev
			}
		}
	}
	return idx
}

// find 在索引内查找去重命中项。
func (idx dedupIndex) find(evType string, nodeID int64) *model.RiskEvent {
	return idx[dedupKey{typ: evType, nodeID: nodeID}]
}

// ruleContext 规则评估上下文
type ruleContext struct {
	d        *Detector
	sessions []model.Session
	now      time.Time

	// 本轮评估用的引擎快照。
	//
	// 规则里到处是"这条会话的内网侧节点是谁""这个 IP 属于哪个域"，
	// 原来每问一次都要回引擎抢一次读锁：一轮 4 万会话就要抢十几万次，
	// 而同一时刻探针写入方在抢写锁——Go 的 RWMutex 会让等待中的写者
	// 挡住后续读者，于是长读循环 + 高频写 = 护航效应。
	// 实测 4 万会话时单轮评估 5.5 秒（同样逻辑单线程只要 0.4 秒），
	// 其中大部分时间花在等锁上。
	nodes   []model.Node           // AllNodes 快照
	byIP    map[string]*model.Node // IP → 节点
	byID    map[int64]*model.Node  // ID → 节点
	domains []domainMatcher        // 预解析好的域规则
}

// domainMatcher 预解析的网络域规则（CIDR 只解析一次，不是每个 IP 解析一次）。
type domainMatcher struct {
	name string
	net  *net.IPNet
	ones int
}

// newNodeIndex 从引擎取一份快照并建索引（一轮一次）。
func (rc *ruleContext) newNodeIndex() {
	rc.nodes = rc.d.Engine.AllNodes()
	rc.byIP = make(map[string]*model.Node, 1024)
	rc.byID = make(map[int64]*model.Node, len(rc.nodes))
	for i := range rc.nodes {
		n := &rc.nodes[i]
		rc.byID[n.ID] = n
		for _, ip := range n.IPs {
			if _, ok := rc.byIP[ip]; !ok {
				rc.byIP[ip] = n
			}
		}
	}
	for _, d := range rc.d.Engine.Domains() {
		for _, c := range d.CIDRs {
			_, ipnet, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			rc.domains = append(rc.domains, domainMatcher{name: d.Name, net: ipnet, ones: ones})
		}
	}
}

// newRuleContext 构造一轮评估的上下文（正式路径与测试共用同一个入口）。
func newRuleContext(d *Detector, sessions []model.Session, now time.Time) *ruleContext {
	rc := &ruleContext{d: d, sessions: sessions, now: now}
	rc.newNodeIndex()
	return rc
}

// nodeByIP 在快照里查 IP 归属节点。
// 快照未初始化时回落到引擎：宁可慢一点，也不能让规则静默失效——
// 一个"查不到节点就跳过"的规则是不报错的，坏起来无声无息。
func (rc *ruleContext) nodeByIP(ip string) *model.Node {
	if rc.byIP == nil {
		return rc.d.Engine.NodeByIP(ip)
	}
	return rc.byIP[ip]
}

// nodeByID 在快照里按 ID 查节点（无锁）。
func (rc *ruleContext) nodeByID(id int64) *model.Node {
	if rc.byID == nil {
		return rc.d.Engine.GetNode(id)
	}
	return rc.byID[id]
}

// allNodes 返回本轮节点快照（未初始化时回落到引擎）。
func (rc *ruleContext) allNodes() []model.Node {
	if rc.byIP == nil {
		return rc.d.Engine.AllNodes()
	}
	return rc.nodes
}

// matchDomain 与 Engine.MatchDomainPrefix 语义一致：取最长前缀命中的域。
func (rc *ruleContext) matchDomain(ipStr string) (string, int) {
	if rc.byIP == nil {
		return rc.d.Engine.MatchDomainPrefix(ipStr)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", -1
	}
	best, bestOnes := "", -1
	for i := range rc.domains {
		dm := &rc.domains[i]
		if dm.net.Contains(ip) && dm.ones > bestOnes {
			best, bestOnes = dm.name, dm.ones
		}
	}
	return best, bestOnes
}

// internalNodeOf 返回会话内网侧节点（优先源侧）。
func (rc *ruleContext) internalNodeOf(s *model.Session) *model.Node {
	if topology.IsPrivate(s.FiveTuple.SrcIP) {
		return rc.nodeByIP(s.FiveTuple.SrcIP)
	}
	if topology.IsPrivate(s.FiveTuple.DstIP) {
		return rc.nodeByIP(s.FiveTuple.DstIP)
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
