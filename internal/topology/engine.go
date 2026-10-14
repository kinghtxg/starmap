// Package topology 拓扑生长引擎（SPEC §4 + §10.3 降噪 + §10.10 聚合迟滞）。
// 增量消费 model.Session，维护节点/边的内存拓扑：
//   - 每个内网 IP → 节点候选；同 MAC 多 IP 合并
//   - 同 /24 内网节点数 > 聚合阈值 → 聚合为子网节点（Snapshot 隐藏成员，可 SubnetSnapshot 下钻）
//   - 公网 IP 不逐一建节点，按 /24 聚合为"外部聚合节点"
//   - 降噪：bytes<阈值 AND duration<阈值 AND packets<阈值 → 不建边
//   - 老化：边超过 aging_seconds 无流量 → Active=false
//   - NAT 修复：以 MAC 归属推断真实源；记录首跳网关 MAC
package topology

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"starmap/internal/model"
)

// 节点标签
const (
	LabelSubnetAgg  = "subnet-agg"   // 子网聚合节点
	LabelExternalAg = "external-agg" // 公网 /24 外部聚合节点
	LabelProbe      = "probe"        // 主动探测发现
)

type edgeKey struct {
	a, b  int64
	proto string
}

// 会话幂等摄入状态（同一会话可能多次 Ingest，只累计增量）
type sessState struct {
	packets  int64
	bytes    int64
	lastSeen time.Time
}

// Engine 拓扑生长引擎（并发安全）
type Engine struct {
	mu sync.RWMutex

	agingSeconds     int64
	aggThreshold     int
	noiseBytes       int64
	noisePackets     int64
	noiseDurationSec int64

	nextNodeID int64
	nextEdgeID int64

	nodes   map[int64]*model.Node // 全部节点（内网真实节点 + 外部聚合节点）
	ipNode  map[string]int64      // 内网 IP → 节点
	macNode map[string]int64      // MAC → 节点（同 MAC 多 IP 合并）
	extAggr map[string]int64      // 公网 /24 CIDR → 外部聚合节点
	edges   map[edgeKey]*model.Edge

	gatewayMAC map[int64]string // 节点 → 首跳网关 MAC（NAT 修复/多网融合"同路由"）

	subnetMembers map[string]map[int64]bool // 内网 /24 CIDR → 成员节点集合
	aggregated    map[string]bool           // 已聚合的 /24（迟滞：一旦聚合不因回落而拆分）

	sessions map[string]*sessState // 会话幂等摄入
	domains  []model.NetDomain     // 网络域（用于节点 Domain 归属）
}

// New 创建拓扑引擎。
func New(cfg model.SystemConfig) *Engine {
	e := &Engine{
		agingSeconds:     cfg.AgingSeconds,
		aggThreshold:     cfg.AggregateThreshold,
		noiseBytes:       cfg.NoiseBytes,
		noisePackets:     cfg.NoisePackets,
		noiseDurationSec: cfg.NoiseDurationSec,
		nextNodeID:       1,
		nextEdgeID:       1,
		nodes:            map[int64]*model.Node{},
		ipNode:           map[string]int64{},
		macNode:          map[string]int64{},
		extAggr:          map[string]int64{},
		edges:            map[edgeKey]*model.Edge{},
		gatewayMAC:       map[int64]string{},
		subnetMembers:    map[string]map[int64]bool{},
		aggregated:       map[string]bool{},
		sessions:         map[string]*sessState{},
	}
	if e.agingSeconds <= 0 {
		e.agingSeconds = 86400
	}
	if e.aggThreshold <= 0 {
		e.aggThreshold = 20
	}
	if e.noiseBytes <= 0 {
		e.noiseBytes = 400
	}
	if e.noisePackets <= 0 {
		e.noisePackets = 4
	}
	if e.noiseDurationSec <= 0 {
		e.noiseDurationSec = 2
	}
	return e
}

// UpdateConfig 热更新参数（PUT /api/config 联动）。
// §10.10：聚合阈值下调立即重聚合；上调不拆分已聚合节点（迟滞）。
func (e *Engine) UpdateConfig(cfg model.SystemConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cfg.AgingSeconds > 0 {
		e.agingSeconds = cfg.AgingSeconds
	}
	if cfg.NoiseBytes > 0 {
		e.noiseBytes = cfg.NoiseBytes
	}
	if cfg.NoisePackets > 0 {
		e.noisePackets = cfg.NoisePackets
	}
	if cfg.NoiseDurationSec > 0 {
		e.noiseDurationSec = cfg.NoiseDurationSec
	}
	if cfg.AggregateThreshold > 0 && cfg.AggregateThreshold != e.aggThreshold {
		e.aggThreshold = cfg.AggregateThreshold
		// 重新评估所有网段（仅可能新增聚合，绝不拆分）
		for cidr, members := range e.subnetMembers {
			if !e.aggregated[cidr] && len(members) > e.aggThreshold {
				e.aggregated[cidr] = true
			}
		}
	}
}

// IsPrivate 判断 RFC1918/ULA/链路本地等内网地址。
func IsPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func cidr24(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	// IPv6 按 /64 聚合
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Ingest 增量摄入一条会话（可重复调用，内部按增量幂等累计）。
func (e *Engine) Ingest(s *model.Session) {
	if s == nil || s.FiveTuple.SrcIP == "" || s.FiveTuple.DstIP == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	key := s.FiveTuple.Key()
	st, ok := e.sessions[key]
	if !ok {
		st = &sessState{}
		e.sessions[key] = st
	}
	totalBytes := s.BytesUp + s.BytesDown
	deltaBytes := totalBytes - st.bytes
	deltaPackets := s.Packets - st.packets
	if deltaBytes < 0 {
		deltaBytes = 0
	}
	if deltaPackets < 0 {
		deltaPackets = 0
	}
	first := st.lastSeen.IsZero()
	st.bytes = totalBytes
	st.packets = s.Packets
	st.lastSeen = s.LastSeen

	now := s.LastSeen
	if now.IsZero() {
		now = time.Now()
	}

	// ---- 节点生长（含 NAT 修复） ----
	srcID := e.nodeForLocked(s.FiveTuple.SrcIP, s.MAC, now)
	dstID := e.nodeForLocked(s.FiveTuple.DstIP, "", now)

	// 首跳网关推断：内网 → 公网 会话的客户端方向 DstMAC 即网关 MAC
	if IsPrivate(s.FiveTuple.SrcIP) && !IsPrivate(s.FiveTuple.DstIP) && s.DstMAC != "" {
		if s.DstMAC != s.MAC { // 非本机直连
			e.gatewayMAC[srcID] = s.DstMAC
		}
	}

	// ---- 降噪（SPEC §10.3）：三条件同时满足 → 不建边 ----
	duration := s.LastSeen.Sub(s.FirstSeen).Seconds()
	if totalBytes < e.noiseBytes && duration < float64(e.noiseDurationSec) && s.Packets < e.noisePackets {
		return
	}
	if first && deltaBytes == 0 && deltaPackets == 0 {
		return
	}

	// ---- 边生长 ----
	ek := edgeKey{a: srcID, b: dstID, proto: s.FiveTuple.Proto}
	if ek.a > ek.b {
		ek.a, ek.b = ek.b, ek.a // 无向链路归一
	}
	edge, ok := e.edges[ek]
	if !ok {
		edge = &model.Edge{
			ID:        e.nextEdgeID,
			SrcID:     ek.a,
			DstID:     ek.b,
			Protocol:  s.FiveTuple.Proto,
			FirstSeen: s.FirstSeen,
			Active:    true,
		}
		e.nextEdgeID++
		e.edges[ek] = edge
	}
	edge.Bytes += deltaBytes
	edge.Packets += deltaPackets
	if s.LastSeen.After(edge.LastSeen) {
		edge.LastSeen = s.LastSeen
	}
	edge.Active = true
	if s.FirstSeen.Before(edge.FirstSeen) {
		edge.FirstSeen = s.FirstSeen
	}

	// 更新节点活跃时间
	for _, id := range []int64{srcID, dstID} {
		if n := e.nodes[id]; n != nil {
			if s.LastSeen.After(n.LastSeen) {
				n.LastSeen = s.LastSeen
			}
			if s.FirstSeen.Before(n.FirstSeen) {
				n.FirstSeen = s.FirstSeen
			}
			n.Active = true
		}
	}
}

// nodeForLocked 返回 IP 对应节点 ID（不存在则创建）。
// NAT 修复：若 mac 已归属某节点而 IP 不同——
//   - 新 IP 为内网 → 合并进该节点（同 MAC 多 IP）
//   - 新 IP 为公网 → 判定为 NAT 后地址，仍归属该节点（链路指向真实源）
func (e *Engine) nodeForLocked(ip, mac string, now time.Time) int64 {
	// 同 MAC 合并 / NAT 修复
	if mac != "" {
		if id, ok := e.macNode[mac]; ok {
			n := e.nodes[id]
			if IsPrivate(ip) && !contains(n.IPs, ip) {
				n.IPs = append(n.IPs, ip)
				sort.Strings(n.IPs)
				e.ipNode[ip] = id
				e.addSubnetMemberLocked(id, ip)
			}
			if now.After(n.LastSeen) {
				n.LastSeen = now
			}
			return id
		}
	}
	if id, ok := e.ipNode[ip]; ok {
		if mac != "" {
			e.macNode[mac] = id
			if e.nodes[id].MAC == "" {
				e.nodes[id].MAC = mac
			}
		}
		return id
	}

	if !IsPrivate(ip) {
		// 公网 IP：按 /24 聚合为外部聚合节点
		cidr := cidr24(ip)
		if id, ok := e.extAggr[cidr]; ok {
			n := e.nodes[id]
			if now.After(n.LastSeen) {
				n.LastSeen = now
			}
			return id
		}
		n := &model.Node{
			ID:        e.nextNodeID,
			IPs:       []string{cidr},
			FirstSeen: now,
			LastSeen:  now,
			Domain:    "internet",
			Labels:    []string{LabelExternalAg},
			RiskLevel: model.RiskNone,
			Active:    true,
		}
		e.nextNodeID++
		e.nodes[n.ID] = n
		e.extAggr[cidr] = n.ID
		return n.ID
	}

	// 内网新节点
	n := &model.Node{
		ID:        e.nextNodeID,
		IPs:       []string{ip},
		MAC:       mac,
		FirstSeen: now,
		LastSeen:  now,
		Domain:    e.matchDomainLocked(ip),
		RiskLevel: model.RiskNone,
		Active:    true,
	}
	e.nextNodeID++
	e.nodes[n.ID] = n
	e.ipNode[ip] = n.ID
	if mac != "" {
		e.macNode[mac] = n.ID
	}
	e.addSubnetMemberLocked(n.ID, ip)
	return n.ID
}

func (e *Engine) addSubnetMemberLocked(id int64, ip string) {
	cidr := cidr24(ip)
	if cidr == "" {
		return
	}
	set, ok := e.subnetMembers[cidr]
	if !ok {
		set = map[int64]bool{}
		e.subnetMembers[cidr] = set
	}
	set[id] = true
	// §4 + §10.10：超过阈值聚合；已聚合的保持聚合（迟滞）
	if !e.aggregated[cidr] && len(set) > e.aggThreshold {
		e.aggregated[cidr] = true
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// matchDomainLocked 按网络域 CIDR 匹配节点归属。
// 最长前缀优先：避免 0.0.0.0/0 之类的宽域遮蔽更精确的域（如 prod 192.168.0.0/16）。
func (e *Engine) matchDomainLocked(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	best := ""
	bestOnes := -1
	for _, d := range e.domains {
		for _, c := range d.CIDRs {
			_, ipnet, err := net.ParseCIDR(c)
			if err != nil || !ipnet.Contains(parsed) {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones > bestOnes {
				bestOnes = ones
				best = d.Name
			}
		}
	}
	return best
}

// SetDomains 设置网络域并重算全部节点归属（domains CRUD 联动）。
func (e *Engine) SetDomains(ds []model.NetDomain) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domains = append([]model.NetDomain(nil), ds...)
	for _, n := range e.nodes {
		if hasLabel(n, LabelExternalAg) {
			continue
		}
		n.Domain = ""
		for _, ip := range n.IPs {
			if d := e.matchDomainLocked(ip); d != "" {
				n.Domain = d
				break
			}
		}
	}
}

// MatchDomain 查询单个 IP 的网络域归属（detect 模块使用）。
func (e *Engine) MatchDomain(ip string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.matchDomainLocked(ip)
}

// GatewayMAC 返回节点的首跳网关 MAC（无则空串）。
func (e *Engine) GatewayMAC(nodeID int64) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.gatewayMAC[nodeID]
}

// SetNodeRisk 设置节点风险等级（事件联动：high→high，mid→mid）。
func (e *Engine) SetNodeRisk(nodeID int64, level string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n, ok := e.nodes[nodeID]; ok {
		n.RiskLevel = level
	}
}

// AddNodeLabel 给节点打标签（只打标签，不定性）。
func (e *Engine) AddNodeLabel(nodeID int64, label string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n, ok := e.nodes[nodeID]; ok && !contains(n.Labels, label) {
		n.Labels = append(n.Labels, label)
	}
}

// GetNode 按 ID 查询节点。
func (e *Engine) GetNode(id int64) *model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if n, ok := e.nodes[id]; ok {
		cp := *n
		return &cp
	}
	return nil
}

// NodeByIP 按内网 IP 查节点。
func (e *Engine) NodeByIP(ip string) *model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if id, ok := e.ipNode[ip]; ok {
		cp := *e.nodes[id]
		return &cp
	}
	return nil
}

// ObserveHost 主动探测结果注入：创建/激活节点。
func (e *Engine) ObserveHost(ip, mac string, ts time.Time) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := e.nodeForLocked(ip, mac, ts)
	n := e.nodes[id]
	n.Active = true
	if ts.After(n.LastSeen) {
		n.LastSeen = ts
	}
	if !contains(n.Labels, LabelProbe) {
		n.Labels = append(n.Labels, LabelProbe)
	}
	return id
}

// Age 执行一次老化扫描：超过 agingSeconds 无流量的边/节点置灰。
func (e *Engine) Age(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-time.Duration(e.agingSeconds) * time.Second)
	for _, edge := range e.edges {
		if edge.Active && edge.LastSeen.Before(cutoff) {
			edge.Active = false
		}
	}
	for _, n := range e.nodes {
		if n.Active && n.LastSeen.Before(cutoff) {
			n.Active = false
		}
	}
}

// RunAging 启动周期性老化 goroutine，ctx 取消即退出。
func (e *Engine) RunAging(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				e.Age(now)
			}
		}
	}()
}

// IsAggregated 查询某 /24 网段是否处于聚合态。
func (e *Engine) IsAggregated(cidr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.aggregated[cidr]
}

// SubnetCIDRs 返回当前已聚合的网段列表。
func (e *Engine) SubnetCIDRs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.aggregated))
	for c := range e.aggregated {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Members 返回聚合网段的成员节点。
func (e *Engine) Members(cidr string) []model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	set := e.subnetMembers[cidr]
	out := make([]model.Node, 0, len(set))
	for id := range set {
		if n, ok := e.nodes[id]; ok {
			out = append(out, *n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SubnetNodeID 返回网段聚合节点在快照中的稳定字符串 ID。
func SubnetNodeID(cidr string) string { return "subnet:" + cidr }

// ExternalNodeID 返回外部聚合节点的稳定字符串 ID。
func ExternalNodeID(cidr string) string { return "ext:" + cidr }

// APINodeID 节点在 API/快照中的字符串 ID。
func APINodeID(n *model.Node) string {
	if hasLabel(n, LabelSubnetAgg) && len(n.IPs) > 0 {
		return SubnetNodeID(n.IPs[0])
	}
	if hasLabel(n, LabelExternalAg) && len(n.IPs) > 0 {
		return ExternalNodeID(n.IPs[0])
	}
	return strconv.FormatInt(n.ID, 10)
}

func hasLabel(n *model.Node, l string) bool { return contains(n.Labels, l) }

// Snapshot 生成拓扑快照：聚合网段的成员隐藏为子网节点。
// 边的可见视图用 SnapshotEdgePairs（端点为字符串身份）获取。
func (e *Engine) Snapshot() model.TopoSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var nodes []model.Node
	for _, n := range e.nodes {
		if !hasLabel(n, LabelExternalAg) {
			// 内网节点：若所属 /24 已聚合则隐藏
			hidden := false
			for _, ip := range n.IPs {
				if e.aggregated[cidr24(ip)] {
					hidden = true
					break
				}
			}
			if hidden {
				continue
			}
		}
		nodes = append(nodes, *n)
	}

	// 生成聚合子网虚拟节点
	for cidr, set := range e.subnetMembers {
		if !e.aggregated[cidr] {
			continue
		}
		agg := model.Node{
			IPs:       []string{cidr},
			Labels:    []string{LabelSubnetAgg},
			RiskLevel: model.RiskNone,
		}
		for id := range set {
			n := e.nodes[id]
			if n == nil {
				continue
			}
			if agg.FirstSeen.IsZero() || n.FirstSeen.Before(agg.FirstSeen) {
				agg.FirstSeen = n.FirstSeen
			}
			if n.LastSeen.After(agg.LastSeen) {
				agg.LastSeen = n.LastSeen
			}
			if n.Active {
				agg.Active = true
			}
			if riskRank(n.RiskLevel) > riskRank(agg.RiskLevel) {
				agg.RiskLevel = n.RiskLevel
			}
		}
		nodes = append(nodes, agg)
	}

	vEdges := e.visibleEdgesLocked()
	stats := model.TopoStats{NodeCount: len(nodes), EdgeCount: len(vEdges)}
	for _, n := range nodes {
		if n.Active {
			stats.ActiveNodes++
		}
	}
	for _, ve := range vEdges {
		stats.TotalBytes += ve.Bytes
		if ve.Active {
			stats.ActiveEdges++
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return APINodeID(&nodes[i]) < APINodeID(&nodes[j]) })

	return model.TopoSnapshot{
		Nodes:       nodes,
		Stats:       stats,
		GeneratedAt: time.Now().UTC(),
	}
}

// SnapshotEdgePairs 返回快照边（端点已映射为可见字符串身份）。
func (e *Engine) SnapshotEdgePairs() []VisibleEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.visibleEdgesLocked()
}

func (e *Engine) visibleEdgesLocked() []VisibleEdge {
	visible := e.visibleMapLocked()
	type veKey struct{ a, b, proto string }
	ve := map[veKey]*VisibleEdge{}
	var order []veKey
	for _, edge := range e.edges {
		a, oka := visible[edge.SrcID]
		b, okb := visible[edge.DstID]
		if !oka || !okb || a == b {
			continue
		}
		k := veKey{a, b, edge.Protocol}
		if k.a > k.b {
			k.a, k.b = k.b, k.a
		}
		acc, ok := ve[k]
		if !ok {
			acc = &VisibleEdge{Protocol: edge.Protocol, FirstSeen: edge.FirstSeen}
			ve[k] = acc
			order = append(order, k)
		}
		acc.Src = k.a
		acc.Dst = k.b
		acc.Bytes += edge.Bytes
		acc.Packets += edge.Packets
		if edge.LastSeen.After(acc.LastSeen) {
			acc.LastSeen = edge.LastSeen
		}
		if acc.FirstSeen.IsZero() || edge.FirstSeen.Before(acc.FirstSeen) {
			acc.FirstSeen = edge.FirstSeen
		}
		if edge.Active {
			acc.Active = true
		}
	}
	out := make([]VisibleEdge, 0, len(order))
	for _, k := range order {
		out = append(out, *ve[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src < out[j].Src
		}
		return out[i].Dst < out[j].Dst
	})
	return out
}

// VisibleEdge 端点已映射为字符串身份的边。
type VisibleEdge struct {
	Src, Dst  string
	Protocol  string
	Bytes     int64
	Packets   int64
	FirstSeen time.Time
	LastSeen  time.Time
	Active    bool
}

func (e *Engine) visibleMapLocked() map[int64]string {
	visible := map[int64]string{}
	for _, n := range e.nodes {
		if !hasLabel(n, LabelExternalAg) {
			aggCIDR := ""
			for _, ip := range n.IPs {
				c := cidr24(ip)
				if e.aggregated[c] {
					aggCIDR = c
					break
				}
			}
			if aggCIDR != "" {
				visible[n.ID] = SubnetNodeID(aggCIDR)
				continue
			}
		}
		visible[n.ID] = APINodeID(n)
	}
	return visible
}

// SubnetSnapshot 聚合节点下钻：返回成员节点 + 与成员相关的边（SPEC §10.6）。
func (e *Engine) SubnetSnapshot(cidr string) model.TopoSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	set := e.subnetMembers[cidr]
	nodes := make([]model.Node, 0, len(set))
	for id := range set {
		if n, ok := e.nodes[id]; ok {
			nodes = append(nodes, *n)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	visible := e.visibleMapLocked()
	var edges []model.Edge
	stats := model.TopoStats{NodeCount: len(nodes)}
	for _, edge := range e.edges {
		ain := set[edge.SrcID]
		bin := set[edge.DstID]
		if !ain && !bin {
			continue
		}
		edges = append(edges, *edge)
		stats.EdgeCount++
		stats.TotalBytes += edge.Bytes
		if edge.Active {
			stats.ActiveEdges++
		}
	}
	for _, n := range nodes {
		if n.Active {
			stats.ActiveNodes++
		}
	}
	_ = visible
	return model.TopoSnapshot{Nodes: nodes, Edges: edges, Stats: stats, GeneratedAt: time.Now().UTC()}
}

// SubnetVisibleEdges 下钻边（端点字符串身份：成员用真实 ID，外部端点用聚合身份）。
func (e *Engine) SubnetVisibleEdges(cidr string) []VisibleEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	set := e.subnetMembers[cidr]
	visible := e.visibleMapLocked()
	var out []VisibleEdge
	for _, edge := range e.edges {
		ain := set[edge.SrcID]
		bin := set[edge.DstID]
		if !ain && !bin {
			continue
		}
		a := visible[edge.SrcID]
		b := visible[edge.DstID]
		out = append(out, VisibleEdge{
			Src: a, Dst: b, Protocol: edge.Protocol,
			Bytes: edge.Bytes, Packets: edge.Packets,
			FirstSeen: edge.FirstSeen, LastSeen: edge.LastSeen, Active: edge.Active,
		})
	}
	return out
}

func riskRank(l string) int {
	switch l {
	case model.RiskHigh:
		return 3
	case model.RiskMid:
		return 2
	case model.RiskLow:
		return 1
	}
	return 0
}

// ParseAPINodeID 解析 API 字符串节点 ID："subnet:x" / "ext:x" / 数字。
func ParseAPINodeID(id string) (kind string, num int64, cidr string) {
	if strings.HasPrefix(id, "subnet:") {
		return "subnet", 0, strings.TrimPrefix(id, "subnet:")
	}
	if strings.HasPrefix(id, "ext:") {
		return "ext", 0, strings.TrimPrefix(id, "ext:")
	}
	if strings.Contains(id, "/") { // 前端直接把 cidr 当 ID
		return "subnet", 0, id
	}
	if v, err := strconv.ParseInt(id, 10, 64); err == nil {
		return "node", v, ""
	}
	return "", 0, ""
}

// NodeByExternalCIDR 按公网 /24 查外部聚合节点。
func (e *Engine) NodeByExternalCIDR(cidr string) *model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if id, ok := e.extAggr[cidr]; ok {
		cp := *e.nodes[id]
		return &cp
	}
	return nil
}
