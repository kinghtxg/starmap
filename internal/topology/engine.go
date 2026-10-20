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
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
)

// 节点标签
const (
	LabelSubnetAgg  = "subnet-agg"   // 子网聚合节点
	LabelExternalAg = "external-agg" // 公网 /24 外部聚合节点
	LabelProbe      = "probe"        // 主动探测发现

	// V1.8：七层转发链。
	// LabelXFFProxy 标记"请求里带 X-Forwarded-For 的转发节点"（nginx/HAProxy/SLB/API 网关）；
	// LabelXFFClient 标记"只能通过 XFF 还原得知"的客户端——被动侧看不到它的直连流量。
	LabelXFFProxy  = "xff-proxy"
	LabelXFFClient = "xff-client"
	// ProtoXFF 指向"经该代理转发"的关系边（无字节数，仅表达归属/路径）。
	ProtoXFF = "xff"
)

// ---------- 稳定节点身份 NodeKey（P0-2） ----------

// NodeKeyOf 生成节点稳定身份：优先 MAC（mac:<mac>），无 MAC 用主 IP（ip:<ip>）。
// 该 key 不随进程重启变化，用作拓扑持久化主键与白名单 node 维度取值。
func NodeKeyOf(mac, primaryIP string) string {
	if m := strings.TrimSpace(mac); m != "" {
		return "mac:" + strings.ToLower(m)
	}
	return "ip:" + strings.TrimSpace(primaryIP)
}

// ExternalNodeKey 外部聚合节点身份（无 MAC，按公网 /24 聚合）。
func ExternalNodeKey(cidr string) string { return "ext:" + cidr }

// primaryIP 取节点主 IP（IPs 已排序，首个即主 IP）。
func primaryIP(n *model.Node) string {
	if len(n.IPs) == 0 {
		return ""
	}
	return n.IPs[0]
}

// nodeKeyFor 返回节点身份；已确定的身份不再变更（先到为准），
// 避免后续学到 MAC 时改 key 导致库里出现同一节点的两行。
func nodeKeyFor(n *model.Node) string {
	if n.NodeKey != "" {
		return n.NodeKey
	}
	if hasLabel(n, LabelExternalAg) && len(n.IPs) > 0 {
		return ExternalNodeKey(n.IPs[0])
	}
	return NodeKeyOf(n.MAC, primaryIP(n))
}

type edgeKey struct {
	a, b  int64
	proto string
}

// edgeKeyOf 边的无向归一幂等键（端点排序 + 协议）。
func edgeKeyOf(e *model.Edge) edgeKey {
	k := edgeKey{a: e.SrcID, b: e.DstID, proto: e.Protocol}
	if k.a > k.b {
		k.a, k.b = k.b, k.a
	}
	return k
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
	nodeKey map[string]int64      // NodeKey → 节点（稳定身份唯一性保障，P0-2）
	extAggr map[string]int64      // 公网 /24 CIDR → 外部聚合节点
	edges   map[edgeKey]*model.Edge

	gatewayMAC map[int64]string // 节点 → 首跳网关 MAC（NAT 修复/多网融合"同路由"）

	subnetMembers map[string]map[int64]bool // 内网 /24 CIDR → 成员节点集合
	aggregated    map[string]bool           // 已聚合的 /24（迟滞：一旦聚合不因回落而拆分）

	sessions map[string]*sessState // 会话幂等摄入
	domains  []model.NetDomain     // 网络域（用于节点 Domain 归属）

	// 持久化（P0-2）：persist 为 nil 时引擎纯内存（单测场景）
	persist    *store.Store
	dirtyNodes map[int64]bool   // 待落盘节点
	dirtyEdges map[edgeKey]bool // 待落盘边
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
		nodeKey:          map[string]int64{},
		extAggr:          map[string]int64{},
		edges:            map[edgeKey]*model.Edge{},
		gatewayMAC:       map[int64]string{},
		subnetMembers:    map[string]map[int64]bool{},
		aggregated:       map[string]bool{},
		sessions:         map[string]*sessState{},
		dirtyNodes:       map[int64]bool{},
		dirtyEdges:       map[edgeKey]bool{},
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

// ---------- 持久化：启动恢复 + 节流落盘（P0-2） ----------

// AttachStore 绑定持久化存储，并从库里恢复上次运行留下的节点/边。
// 必须在任何 Ingest 之前调用：恢复后 node.ID 沿用库内 id，
// 历史事件的 NodeID 与白名单 node 维度才能跨重启指向同一个节点。
// st 为 nil 时引擎退化为纯内存（单测场景）。
func (e *Engine) AttachStore(st *store.Store) error {
	if st == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.persist = st
	return e.restoreLocked()
}

// restoreLocked 恢复拓扑到内存并重建索引（IP/MAC/NodeKey → 节点、ID → 节点）。
func (e *Engine) restoreLocked() error {
	nodes, err := e.persist.ListNodes()
	if err != nil {
		return err
	}
	var maxNodeID int64
	for i := range nodes {
		n := &nodes[i]
		n.NodeKey = nodeKeyFor(n)
		if _, dup := e.nodeKey[n.NodeKey]; dup || e.nodes[n.ID] != nil {
			continue // 身份重复的行直接忽略，保证 NodeKey 唯一
		}
		e.nodes[n.ID] = n
		e.nodeKey[n.NodeKey] = n.ID
		for _, ip := range n.IPs {
			if !hasLabel(n, LabelExternalAg) {
				e.ipNode[ip] = n.ID
			}
			e.addSubnetMemberLocked(n.ID, ip)
		}
		if n.MAC != "" {
			e.macNode[n.MAC] = n.ID
		}
		if hasLabel(n, LabelExternalAg) && len(n.IPs) > 0 {
			e.extAggr[n.IPs[0]] = n.ID
		}
		if n.ID > maxNodeID {
			maxNodeID = n.ID
		}
	}
	if maxNodeID >= e.nextNodeID {
		e.nextNodeID = maxNodeID + 1
	}

	edges, err := e.persist.ListEdges()
	if err != nil {
		return err
	}
	var maxEdgeID int64
	for i := range edges {
		ed := &edges[i]
		if e.nodes[ed.SrcID] == nil || e.nodes[ed.DstID] == nil {
			continue // 端点已被删除的悬空边
		}
		ek := edgeKeyOf(ed)
		if _, ok := e.edges[ek]; ok {
			continue
		}
		e.edges[ek] = ed
		if ed.ID > maxEdgeID {
			maxEdgeID = ed.ID
		}
	}
	if maxEdgeID >= e.nextEdgeID {
		e.nextEdgeID = maxEdgeID + 1
	}
	// 库内数据即最新快照，恢复本身不产生写回
	e.dirtyNodes = map[int64]bool{}
	e.dirtyEdges = map[edgeKey]bool{}
	return nil
}

// Flush 把累计的脏节点/边一次性批量落盘（幂等 upsert，节点按 id、边按 (src_key,dst_key,protocol)）。
// 调用方通过 RunPersist 以固定间隔驱动，绝不在每个报文里写库。
func (e *Engine) Flush() error {
	e.mu.Lock()
	st := e.persist
	if st == nil || (len(e.dirtyNodes) == 0 && len(e.dirtyEdges) == 0) {
		e.mu.Unlock()
		return nil
	}
	nodeIDs := make([]int64, 0, len(e.dirtyNodes))
	nodes := make([]model.Node, 0, len(e.dirtyNodes))
	for id := range e.dirtyNodes {
		if n := e.nodes[id]; n != nil {
			n.NodeKey = nodeKeyFor(n)
			nodeIDs = append(nodeIDs, id)
			nodes = append(nodes, *n)
		}
	}
	edgeKeys := make([]edgeKey, 0, len(e.dirtyEdges))
	edges := make([]store.EdgeUpsert, 0, len(e.dirtyEdges))
	for k := range e.dirtyEdges {
		ed := e.edges[k]
		if ed == nil {
			continue
		}
		src, dst := e.nodes[ed.SrcID], e.nodes[ed.DstID]
		if src == nil || dst == nil {
			continue
		}
		edgeKeys = append(edgeKeys, k)
		edges = append(edges, store.EdgeUpsert{Edge: *ed, SrcKey: nodeKeyFor(src), DstKey: nodeKeyFor(dst)})
	}
	e.dirtyNodes = map[int64]bool{}
	e.dirtyEdges = map[edgeKey]bool{}
	e.mu.Unlock()

	if len(nodes) > 0 {
		if err := st.UpsertNodes(nodes); err != nil {
			e.remarkDirty(nodeIDs, edgeKeys)
			return err
		}
	}
	if len(edges) > 0 {
		if err := st.UpsertEdges(edges); err != nil {
			e.remarkDirty(nil, edgeKeys)
			return err
		}
	}
	return nil
}

// remarkDirty 写库失败时把脏集合放回去，等待下一轮重试（避免单次抖动丢失拓扑）。
func (e *Engine) remarkDirty(nodeIDs []int64, edgeKeys []edgeKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range nodeIDs {
		e.dirtyNodes[id] = true
	}
	for _, k := range edgeKeys {
		e.dirtyEdges[k] = true
	}
}

// RunPersist 启动后台节流落盘（建议 2s 一次）：只在定时器到期时批量写，
// ctx 取消时补一次 flush，保证优雅退出不丢数据。未绑定存储则不启动。
func (e *Engine) RunPersist(ctx context.Context, interval time.Duration) {
	if e.persist == nil {
		return
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				if err := e.Flush(); err != nil {
					log.Printf("[topology] 退出前拓扑落盘失败: %v", err)
				}
				return
			case <-t.C:
				if err := e.Flush(); err != nil {
					log.Printf("[topology] 拓扑落盘失败: %v", err)
				}
			}
		}
	}()
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

// Subnet24 返回 IP 所属的 /24 网段（IPv6 为 /64）。
// 导出版，供 detect 等包按"实际网段"做多网融合判定（政务网一机多网场景）。
func Subnet24(ipStr string) string { return cidr24(ipStr) }

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

	// 探针位置归纳（V1.3）：会话带来源探针位置 → 内网节点归属该位置。
	// 只标注内网节点，公网聚合节点（ext:）不归属探针位置。
	if s.Location != "" {
		if n := e.nodes[srcID]; n != nil && n.Location == "" {
			n.Location = s.Location
			e.dirtyNodes[srcID] = true
		}
		if IsPrivate(s.FiveTuple.DstIP) {
			if n := e.nodes[dstID]; n != nil && n.Location == "" {
				n.Location = s.Location
				e.dirtyNodes[dstID] = true
			}
		}
	}

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
	ek := edgeKeyOf(&model.Edge{SrcID: srcID, DstID: dstID, Protocol: s.FiveTuple.Proto})
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
	e.dirtyEdges[ek] = true

	// 更新节点活跃时间（变更即标记脏，节流 flush 时批量落盘）
	for _, id := range []int64{srcID, dstID} {
		if n := e.nodes[id]; n != nil {
			if s.LastSeen.After(n.LastSeen) {
				n.LastSeen = s.LastSeen
				e.dirtyNodes[id] = true
			}
			if s.FirstSeen.Before(n.FirstSeen) {
				n.FirstSeen = s.FirstSeen
				e.dirtyNodes[id] = true
			}
			if !n.Active {
				n.Active = true
				e.dirtyNodes[id] = true
			}
		}
	}

	// 七层转发还原（V1.8）：请求带 X-Forwarded-For 时，真实客户端不在这条会话的
	// 五元组里。把 XFF 还原出的客户端补成独立节点，并与转发节点连一条 xff 关系边，
	// 否则"代理后面几百台客户端"在拓扑上完全不存在。
	if s.RealClientIP != "" {
		e.applyForwardedLocked(srcID, s.RealClientIP, now)
	}
}

// applyForwardedLocked 处理一条转发链（调用方持有 e.mu）。
// proxyID 是观测到的请求源（转发节点），clientIP 是 XFF 还原出的真实客户端。
func (e *Engine) applyForwardedLocked(proxyID int64, clientIP string, now time.Time) {
	// 只处理内网客户端：公网客户端归外网聚合节点，不单独建节点
	if clientIP == "" || !IsPrivate(clientIP) {
		return
	}
	proxy := e.nodes[proxyID]
	if proxy == nil {
		return
	}
	// 自我声明（XFF 首跳 == 观测源本身）不算转发关系，交由检测器判可疑；
	// 若仍建节点会得到一个自己连自己的环。
	for _, ip := range proxy.IPs {
		if ip == clientIP {
			return
		}
	}
	clientID := e.nodeForLocked(clientIP, "", now)
	if clientID == proxyID {
		return
	}

	if !contains(proxy.Labels, LabelXFFProxy) {
		proxy.Labels = append(proxy.Labels, LabelXFFProxy)
		e.dirtyNodes[proxyID] = true
	}
	if n := e.nodes[clientID]; n != nil && !contains(n.Labels, LabelXFFClient) {
		n.Labels = append(n.Labels, LabelXFFClient)
		e.dirtyNodes[clientID] = true
	}

	// 关系边：client → proxy，无字节数（不是观测到的流量，而是还原出的路径）
	ek := edgeKeyOf(&model.Edge{SrcID: clientID, DstID: proxyID, Protocol: ProtoXFF})
	edge, ok := e.edges[ek]
	if !ok {
		edge = &model.Edge{
			ID:        e.nextEdgeID,
			SrcID:     ek.a,
			DstID:     ek.b,
			Protocol:  ProtoXFF,
			FirstSeen: now,
			LastSeen:  now,
			Active:    true,
		}
		e.nextEdgeID++
		e.edges[ek] = edge
		e.dirtyEdges[ek] = true
		return
	}
	if now.After(edge.LastSeen) {
		edge.LastSeen = now
		edge.Active = true
		e.dirtyEdges[ek] = true
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
				e.dirtyNodes[id] = true
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
			// NodeKey 一经确定不再改写（避免库里出现同一节点的两行身份）
			if e.nodes[id].NodeKey == "" {
				e.nodes[id].NodeKey = NodeKeyOf(mac, primaryIP(e.nodes[id]))
			}
			e.dirtyNodes[id] = true
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
		key := ExternalNodeKey(cidr)
		if id, ok := e.nodeKey[key]; ok { // 幂等：库里已有同一 /24 聚合节点
			return id
		}
		n := &model.Node{
			ID:        e.nextNodeID,
			NodeKey:   key,
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
		e.nodeKey[n.NodeKey] = n.ID
		e.extAggr[cidr] = n.ID
		e.dirtyNodes[n.ID] = true
		return n.ID
	}

	// 内网新节点
	n := &model.Node{
		ID:        e.nextNodeID,
		NodeKey:   NodeKeyOf(mac, ip),
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
	e.nodeKey[n.NodeKey] = n.ID
	e.ipNode[ip] = n.ID
	if mac != "" {
		e.macNode[mac] = n.ID
	}
	e.addSubnetMemberLocked(n.ID, ip)
	e.dirtyNodes[n.ID] = true
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
		want := ""
		for _, ip := range n.IPs {
			if d := e.matchDomainLocked(ip); d != "" {
				want = d
				break
			}
		}
		if n.Domain != want {
			n.Domain = want
			e.dirtyNodes[n.ID] = true
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
		e.dirtyNodes[nodeID] = true
	}
}

// AddNodeLabel 给节点打标签（只打标签，不定性）。
func (e *Engine) AddNodeLabel(nodeID int64, label string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n, ok := e.nodes[nodeID]; ok && !contains(n.Labels, label) {
		n.Labels = append(n.Labels, label)
		e.dirtyNodes[nodeID] = true
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
	e.dirtyNodes[id] = true
	return id
}

// RemoveNodeByKey 按稳定 NodeKey 删除节点及其关联边（V1.2 账外资产离线清理）。
// 返回是否删除成功。
func (e *Engine) RemoveNodeByKey(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.nodeKey[key]
	if !ok {
		return false
	}
	return e.removeNodeLocked(id)
}

// removeNodeLocked 删除节点（调用方需持锁）。清理节点、索引、关联边、聚合成员。
func (e *Engine) removeNodeLocked(id int64) bool {
	n, ok := e.nodes[id]
	if !ok {
		return false
	}
	// 清理 IP/MAC/NodeKey 索引
	for _, ip := range n.IPs {
		if e.ipNode[ip] == id {
			delete(e.ipNode, ip)
		}
	}
	if n.MAC != "" && e.macNode[n.MAC] == id {
		delete(e.macNode, n.MAC)
	}
	if n.NodeKey != "" {
		delete(e.nodeKey, n.NodeKey)
	}
	// 外部聚合节点清理 extAggr
	for cidr, nid := range e.extAggr {
		if nid == id {
			delete(e.extAggr, cidr)
		}
	}
	// 清理关联边
	for k, edge := range e.edges {
		if edge.SrcID == id || edge.DstID == id {
			delete(e.edges, k)
			delete(e.dirtyEdges, k)
		}
	}
	// 清理聚合成员
	for cidr, members := range e.subnetMembers {
		if members[id] {
			delete(members, id)
			if len(members) == 0 {
				delete(e.subnetMembers, cidr)
			}
		}
	}
	delete(e.gatewayMAC, id)
	delete(e.nodes, id)
	delete(e.dirtyNodes, id)
	if e.persist != nil {
		_ = e.persist.DeleteNode(id)
	}
	return true
}

// Age 执行一次老化扫描：超过 agingSeconds 无流量的边/节点置灰。
func (e *Engine) Age(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-time.Duration(e.agingSeconds) * time.Second)
	for _, edge := range e.edges {
		if edge.Active && edge.LastSeen.Before(cutoff) {
			edge.Active = false
			e.dirtyEdges[edgeKeyOf(edge)] = true
		}
	}
	for id, n := range e.nodes {
		if n.Active && n.LastSeen.Before(cutoff) {
			n.Active = false
			e.dirtyNodes[id] = true
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

// isRiskAnchor 判断节点是否为"风险锚点"。
// V1.6：中/高风险节点（多网融合、隧道、可疑出网等）不参与网段聚合，
// 在拓扑中始终单独呈现。理由——大网里 /24 一旦超过聚合阈值就折叠成一个网段节点，
// 若把异常设备一起折叠，就等于把"最该被看见的那台"藏起来，与项目的核心使命相悖。
// 正常网络没有中/高风险节点，因此该策略对常规大网的可视性零成本。
func isRiskAnchor(n *model.Node) bool {
	return n.RiskLevel == model.RiskHigh || n.RiskLevel == model.RiskMid
}

// visibleAsSelf 判断节点是否"必须以自身身份出现在拓扑里"（不参与网段聚合）。
//
// 两类：
//   - 风险锚点（中/高风险）：异常设备被聚合吞掉等于藏起最该看见的那台（V1.6）
//   - 七层转发节点：它是个结构性的收口点，聚合掉它等于藏起"背后一片客户端"的入口（V1.8）
//
// 注意：转发节点不是"异常"，所以不置 Anchor 字段（那是风险语义，前端据此画红虚环）。
func visibleAsSelf(n *model.Node) bool {
	return isRiskAnchor(n) || hasLabel(n, LabelXFFProxy)
}

// aggNodeLocked 构造网段聚合虚拟节点（调用方需持有 e.mu）。
func (e *Engine) aggNodeLocked(cidr string) (model.Node, bool) {
	set := e.subnetMembers[cidr]
	if len(set) == 0 || !e.aggregated[cidr] {
		return model.Node{}, false
	}
	agg := model.Node{
		IPs:       []string{cidr},
		Labels:    []string{LabelSubnetAgg},
		RiskLevel: model.RiskNone,
		Members:   len(set),
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
	return agg, true
}

// AggregateNode 按 CIDR 取网段聚合虚拟节点（下钻视图作为外部上下文节点使用）。
func (e *Engine) AggregateNode(cidr string) (model.Node, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.aggNodeLocked(cidr)
}

// Snapshot 生成拓扑快照：聚合网段的成员隐藏为子网节点。
// 边的可见视图用 SnapshotEdgePairs（端点为字符串身份）获取。
func (e *Engine) Snapshot() model.TopoSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var nodes []model.Node
	for _, n := range e.nodes {
		if !hasLabel(n, LabelExternalAg) {
			// 内网节点：若所属 /24 已聚合则隐藏——但风险锚点例外（V1.6）
			hidden := false
			for _, ip := range n.IPs {
				if e.aggregated[cidr24(ip)] {
					hidden = true
					break
				}
			}
			if hidden && !visibleAsSelf(n) {
				continue
			}
		}
		cp := *n
		cp.Anchor = isRiskAnchor(n)
		nodes = append(nodes, cp)
	}

	// 生成聚合子网虚拟节点
	cidrs := make([]string, 0, len(e.subnetMembers))
	for cidr := range e.subnetMembers {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)
	for _, cidr := range cidrs {
		if agg, ok := e.aggNodeLocked(cidr); ok {
			nodes = append(nodes, agg)
		}
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

// SubnetInfo 网段清单条目（V1.4）：内网 /24 网段的汇总视图。
// 直接回答"网内结构"：有哪些网段、每网段多少台、在线几台、网关是谁、风险如何。
type SubnetInfo struct {
	CIDR       string `json:"cidr"`
	HostCount  int    `json:"host_count"`
	Online     int    `json:"online"`
	Aggregated bool   `json:"aggregated"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
	Location   string `json:"location,omitempty"`
	RiskCount  int    `json:"risk_count"` // 网段内 high 风险节点数
	RiskLevel  string `json:"risk_level"` // 网段内最高风险等级
}

// Subnets 返回全部已发现的内网 /24 网段（含未聚合的），附带统计。
// 与 SubnetCIDRs（只返回已聚合网段）不同，这里不隐藏任何网段。
func (e *Engine) Subnets() []SubnetInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]SubnetInfo, 0, len(e.subnetMembers))
	for cidr, set := range e.subnetMembers {
		info := SubnetInfo{CIDR: cidr, Aggregated: e.aggregated[cidr], RiskLevel: model.RiskNone}
		gwCount := map[string]int{}
		locCount := map[string]int{}
		for id := range set {
			n := e.nodes[id]
			if n == nil {
				continue
			}
			info.HostCount++
			if n.Active {
				info.Online++
			}
			if n.RiskLevel == model.RiskHigh {
				info.RiskCount++
			}
			if riskRank(n.RiskLevel) > riskRank(info.RiskLevel) {
				info.RiskLevel = n.RiskLevel
			}
			if gw := e.gatewayMAC[id]; gw != "" {
				gwCount[gw]++
			}
			if n.Location != "" {
				locCount[n.Location]++
			}
		}
		info.GatewayMAC = mostFrequent(gwCount)
		info.Location = mostFrequent(locCount)
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// ProxyInfo 七层转发节点及其背后的真实客户端（V1.8）。
type ProxyInfo struct {
	NodeID    int64     `json:"node_id"`
	IPs       []string  `json:"ips"`
	MAC       string    `json:"mac"`
	Clients   int       `json:"clients"`
	ClientIPs []string  `json:"client_ips"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Active    bool      `json:"active"`
}

// Proxies 返回全部已识别的七层转发节点，以及经它们转发的真实客户端清单。
//
// 从协议为 xff 的关系边推导（而不是另存一份内存表），因此重启后能从持久化边恢复。
// 用途：回答"这个代理后面到底有多少台设备、都是谁"——这些设备被动侧看不到直连流量。
func (e *Engine) Proxies() []ProxyInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	byProxy := map[int64]*ProxyInfo{}
	for _, edge := range e.edges {
		if edge.Protocol != ProtoXFF {
			continue
		}
		a, b := e.nodes[edge.SrcID], e.nodes[edge.DstID]
		if a == nil || b == nil {
			continue
		}
		var proxy, client *model.Node
		switch {
		case hasLabel(a, LabelXFFProxy):
			proxy, client = a, b
		case hasLabel(b, LabelXFFProxy):
			proxy, client = b, a
		default:
			continue
		}
		info := byProxy[proxy.ID]
		if info == nil {
			info = &ProxyInfo{
				NodeID:    proxy.ID,
				IPs:       proxy.IPs,
				MAC:       proxy.MAC,
				Active:    proxy.Active,
				FirstSeen: edge.FirstSeen,
				LastSeen:  edge.LastSeen,
			}
			byProxy[proxy.ID] = info
		}
		if len(client.IPs) > 0 {
			info.ClientIPs = append(info.ClientIPs, client.IPs[0])
		}
		if edge.FirstSeen.Before(info.FirstSeen) || info.FirstSeen.IsZero() {
			info.FirstSeen = edge.FirstSeen
		}
		if edge.LastSeen.After(info.LastSeen) {
			info.LastSeen = edge.LastSeen
		}
	}

	out := make([]ProxyInfo, 0, len(byProxy))
	for _, info := range byProxy {
		sort.Strings(info.ClientIPs)
		info.Clients = len(info.ClientIPs)
		out = append(out, *info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Clients != out[j].Clients {
			return out[i].Clients > out[j].Clients // 客户端多的排前面
		}
		if len(out[i].IPs) == 0 || len(out[j].IPs) == 0 {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].IPs[0] < out[j].IPs[0]
	})
	return out
}

// mostFrequent 返回计数最多的键（并列时取字典序最小，保证稳定）。
func mostFrequent(m map[string]int) string {
	best, bestN := "", 0
	for k, n := range m {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

// AllNodes 返回全部内网真实节点（不含外部聚合节点，也**不隐藏**已聚合网段的成员）。
// 与 Snapshot 的区别：Snapshot 为拓扑展示会把聚合网段的成员隐藏掉，导致
// 资产同步/多网段判定漏掉绝大多数主机（V1.4 P0 修复）。
func (e *Engine) AllNodes() []model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]model.Node, 0, len(e.nodes))
	for _, n := range e.nodes {
		if hasLabel(n, LabelExternalAg) || strings.HasPrefix(n.NodeKey, "ext:") {
			continue
		}
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return APINodeID(&out[i]) < APINodeID(&out[j]) })
	return out
}

// SnapshotEdgePairs 返回快照边（端点已映射为可见字符串身份）。
// 末尾追加风险锚点的网段归属边（Kind="owner"），使一机两网的跨网归属在图上可见。
func (e *Engine) SnapshotEdgePairs() []VisibleEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := e.visibleEdgesLocked()
	return append(out, e.ownershipEdgesLocked(out)...)
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
	// Kind 边类型："traffic"（默认，由实际会话产生）/ "owner"（归属关联，V1.6）。
	// owner 边由节点自身 IP 的 /24 归属推导，无流量也会存在，
	// 目的：让"一机两网"的跨网归属在图上可见，而不必依赖该网段内恰好有内部对端。
	Kind string
}

// EdgeKindOwner 归属关联边。
const EdgeKindOwner = "owner"

// ownershipEdgesLocked 生成风险锚点的网段归属边（调用方需持有 e.mu）。
// 仅对以自身身份可见的节点生成；若该节点与目标网段之间已有真实流量边，则跳过以免重线。
func (e *Engine) ownershipEdgesLocked(existing []VisibleEdge) []VisibleEdge {
	paired := map[string]bool{}
	for _, ed := range existing {
		if ed.Kind == EdgeKindOwner {
			continue
		}
		paired[ed.Src+"|"+ed.Dst] = true
		paired[ed.Dst+"|"+ed.Src] = true
	}
	var out []VisibleEdge
	for _, n := range e.nodes {
		if hasLabel(n, LabelExternalAg) || !isRiskAnchor(n) {
			continue
		}
		src := APINodeID(n)
		for _, ip := range n.IPs {
			cidr := cidr24(ip)
			if !e.aggregated[cidr] {
				continue
			}
			dst := SubnetNodeID(cidr)
			if dst == src || paired[src+"|"+dst] || paired[dst+"|"+src] {
				continue
			}
			paired[src+"|"+dst] = true
			out = append(out, VisibleEdge{
				Src: src, Dst: dst, Protocol: "owner", Kind: EdgeKindOwner,
				FirstSeen: n.FirstSeen, LastSeen: n.LastSeen, Active: n.Active,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src < out[j].Src
		}
		return out[i].Dst < out[j].Dst
	})
	return out
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
			if aggCIDR != "" && !visibleAsSelf(n) {
				// V1.6：风险锚点不折叠，保持自身身份，从而与两个网段聚合节点同时相连，
				// 在图上直接呈现"一机跨两网"的拓扑签名。
				// V1.8：七层转发节点同样常驻，否则聚合会把"代理 + 背后一片客户端"一起吞掉。
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
			cp := *n
			cp.Anchor = isRiskAnchor(n)
			nodes = append(nodes, cp)
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

// SubnetVisibleEdges 下钻边（端点字符串身份：本网段成员用真实 ID，外部端点用聚合身份）。
//
// V1.6 修复（P1）：成员此前一律经 visibleMapLocked 映射成 subnet:<自身 CIDR>，
// 导致下钻视图里所有网段内链路的两个端点都是同一个聚合 ID 而被前端丢弃，
// 于是"下钻一个 /24"只看得到一堆孤立圆点，看不到主机之间谁连谁——
// 而这正是"理清网内结构"最需要看的东西。
func (e *Engine) SubnetVisibleEdges(cidr string) []VisibleEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	set := e.subnetMembers[cidr]
	visible := e.visibleMapLocked()
	// 成员优先用自身真实身份；非成员才退回可见映射（可能是别的网段的聚合身份）
	idOf := func(id int64) string {
		if set[id] {
			if n, ok := e.nodes[id]; ok {
				// 成员所在 /24 已聚合时，visible 会给 subnet:cidr；
				// 但下钻视图的真实节点 ID 是本节点自身，必须用它。
				return strconv.FormatInt(n.ID, 10)
			}
		}
		return visible[id]
	}
	var out []VisibleEdge
	for _, edge := range e.edges {
		ain := set[edge.SrcID]
		bin := set[edge.DstID]
		if !ain && !bin {
			continue
		}
		a := idOf(edge.SrcID)
		b := idOf(edge.DstID)
		if a == "" || b == "" || a == b {
			continue
		}
		out = append(out, VisibleEdge{
			Src: a, Dst: b, Protocol: edge.Protocol,
			Bytes: edge.Bytes, Packets: edge.Packets,
			FirstSeen: edge.FirstSeen, LastSeen: edge.LastSeen, Active: edge.Active,
		})
	}
	// 归属边：只保留本网段成员发出的归属，避免别的网段的锚点边串进本视图
	memberIDs := make(map[string]bool, len(set))
	for id := range set {
		memberIDs[strconv.FormatInt(id, 10)] = true
	}
	self := SubnetNodeID(cidr)
	for _, ed := range e.ownershipEdgesLocked(out) {
		if ed.Src == self || ed.Dst == self || !memberIDs[ed.Src] {
			continue
		}
		out = append(out, ed)
	}
	return out
}

// SubnetContextNodes 返回下钻视图需要补充的"外部上下文"节点：
// 既包括别的已聚合网段（跨网归属/一机两网），也包括外部 /24 聚合节点（出口方向）。
// 不补这些节点，指向它们的边会因端点缺失被前端整条丢弃，下钻视图就只剩孤立主机（V1.6）。
func (e *Engine) SubnetContextNodes(cidr string, endpoints []string) []model.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	seen := map[string]bool{}
	var out []model.Node
	for _, ep := range endpoints {
		if seen[ep] {
			continue
		}
		switch {
		case strings.HasPrefix(ep, "subnet:"):
			c := strings.TrimPrefix(ep, "subnet:")
			if c == cidr {
				continue
			}
			if agg, ok := e.aggNodeLocked(c); ok {
				seen[ep] = true
				out = append(out, agg)
			}
		case strings.HasPrefix(ep, "ext:"):
			c := strings.TrimPrefix(ep, "ext:")
			if id, ok := e.extAggr[c]; ok {
				if n, ok2 := e.nodes[id]; ok2 {
					seen[ep] = true
					out = append(out, *n)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return APINodeID(&out[i]) < APINodeID(&out[j]) })
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
