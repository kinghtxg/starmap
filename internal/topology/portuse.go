package topology

import (
	"sort"
	"time"

	"starmap/internal/model"
)

// 端口使用统计（V1.9）。
//
// 需求出发点是"点开一台主机，我想知道它连过对方的什么端口"。在此之前拓扑只知道
// "谁和谁有流量"，不知道"走的是哪个端口"——而这恰恰是判断一台机器在干什么的
// 最便宜的证据：连 445 是 SMB，连 3306 是数据库，连 443 可能是正常上网也可能是隧道。
//
// 两个方向都记，语义严格区分：
//
//	outUse  本节点作为客户端 → 对端的服务端口（"它连了对方 443"）
//	inUse   本节点作为服务端 ← 对方连的本端端口（"它的 443 有人连"）
//
// 为什么不用现有的 e.ports：那一份只记"目的地址在内网 + 端口在服务端口表里"的会话，
// 是角色推断的证据，口径必须稳（改了会让 30 个角色用例集体漂移）。而"这台机器连过
// 哪些端口"要的是全量视角：公网节点没有 e.ports（它的目的地址从来不是内网），
// 高端口也不在服务端口表里，两者都正是用户最想问的情况。
const (
	// portUsePerNode 每节点最多保留多少个不同端口。
	// 一台被扫描的机器可能出现上万个目的端口，全留会把内存吃掉；
	// 按会话数排序取前 N 已经能回答"它在干什么"，剩下的长尾没有信息量。
	portUsePerNode = 32
	// portPeerCap 每个端口最多记多少个不同对端（只用于显示"几个对端用过"）。
	portPeerCap = 8
	// portUseOutput 出图时最多给前端多少个端口（再多界面上也读不过来）。
	portUseOutput = 12
)

// portUse 一个端口的使用统计。
type portUse struct {
	port     uint16
	proto    string
	sessions int
	bytes    int64
	peers    map[string]struct{}
	lastSeen time.Time
}

// observePortUseLocked 记录一条会话的端口使用（调用方需持 e.mu）。
//
// first 只在"第一次见到这条会话"时为 true：Ingest 对同一会话会被反复调用
// （探针每 2s 报一次累计值），用它区分"新会话"与"同一会话的增量"，
// 否则一次长连接会被数成几百次连接。
func (e *Engine) observePortUseLocked(srcID, dstID int64, s *model.Session, first bool, deltaBytes int64) {
	port := s.FiveTuple.DstPort
	// 端口 0 只出现在 ICMP / 非端口协议里，画出来就是噪音
	if port == 0 || srcID == dstID {
		return
	}
	proto := s.FiveTuple.Proto

	if u := portUseAdd(e.outUse, srcID, port, proto, s.LastSeen); u != nil {
		if first {
			u.sessions++
		}
		if deltaBytes > 0 {
			u.bytes += deltaBytes
		}
		portUsePeer(u, s.FiveTuple.DstIP)
	}
	if u := portUseAdd(e.inUse, dstID, port, proto, s.LastSeen); u != nil {
		if first {
			u.sessions++
		}
		if deltaBytes > 0 {
			u.bytes += deltaBytes
		}
		portUsePeer(u, s.FiveTuple.SrcIP)
	}
}

// portUseAdd 取（或建）某节点的端口条目；超出每节点上限且是新端口时返回 nil。
//
// 满了就丢弃新端口而不是淘汰旧端口：先到的通常是持续在用的主业务端口，
// 后到的多半是扫描噪音。淘汰会让"主业务端口"在扫描过后消失，那比少显示一个端口更糟。
func portUseAdd(m map[int64]map[uint16]*portUse, id int64, port uint16, proto string, seen time.Time) *portUse {
	set := m[id]
	if set == nil {
		set = map[uint16]*portUse{}
		m[id] = set
	}
	if u, ok := set[port]; ok {
		if seen.After(u.lastSeen) {
			u.lastSeen = seen
		}
		if u.proto == "" {
			u.proto = proto
		}
		return u
	}
	if len(set) >= portUsePerNode {
		return nil
	}
	u := &portUse{port: port, proto: proto, lastSeen: seen}
	set[port] = u
	return u
}

func portUsePeer(u *portUse, ip string) {
	if ip == "" {
		return
	}
	if u.peers == nil {
		u.peers = map[string]struct{}{}
	}
	if len(u.peers) < portPeerCap {
		u.peers[ip] = struct{}{}
	}
}

// topPortUse 把某节点的端口统计转成给前端的列表（按会话数降序，其次端口号）。
//
// 排序不能省：map 迭代无序，前端每次刷新都会看到端口顺序在跳，
// 看起来像"端口在变"，比不显示更让人不信任。
func topPortUse(set map[uint16]*portUse) []model.PortUse {
	if len(set) == 0 {
		return nil
	}
	out := make([]model.PortUse, 0, len(set))
	for _, u := range set {
		out = append(out, model.PortUse{
			Port:     int(u.port),
			Proto:    u.proto,
			Sessions: u.sessions,
			Peers:    len(u.peers),
			Bytes:    u.bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sessions != out[j].Sessions {
			return out[i].Sessions > out[j].Sessions
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > portUseOutput {
		out = out[:portUseOutput]
	}
	return out
}
