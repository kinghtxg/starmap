package parser

import (
	"time"

	"starmap/internal/model"
)

// AbsFlow 探针上报的一次会话快照（绝对值语义）。
//
// 为什么需要单独一条入口（V1.5.1）：
// 探针的会话表是「从会话建立到现在的累计值」，它每隔几秒把有变化的会话整条重发一遍。
// 旧做法是把 flows 折算成合成报文塞进 Aggregator，而 Aggregator 对报文是加法语义
// （BytesUp += Length）——同一条 3MB 的会话被报 300 次，字节数就变成 900MB。
// 实测一条 25 分钟的 HTTPS 长连接被累成 850MB，整库 28GB，而同一时刻本机网卡
// 真实吞吐只有 0.1MB/s。字节数是拓扑、端口、风险评分共用的分母，它错了，
// 界面上所有数字都不可信，而且没有任何地方会报错。
//
// 所以绝对值必须用绝对值的入口：直接赋值，重复上报幂等。
// 下游 topology.Engine 自己按「上次看到的累计值」求差，增量只算一次。
type AbsFlow struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
	MAC     string
	DstMAC  string

	BytesUp   int64
	BytesDown int64
	Packets   int64

	FirstSeen time.Time
	LastSeen  time.Time

	StartTTL   int
	SNI        string
	HTTPHost   string
	JA3        string
	JA4        string
	UserAgent  string
	HTTPServer string

	IsLongConn          bool
	HeartbeatIntervalMs int64

	Location string
	XFF      []string
	XRealIP  string
}

// IngestAbs 用探针上报的会话快照校准聚合器里的会话。
//
// 与 Ingest 的两个关键差别：
//  1. 字节/包数是赋值不是累加 —— 同一份快照重复上报不产生任何流量。
//  2. 只在前进方向更新 —— 本地抓包与探针可能同时看到同一条会话，两边的累计值
//     谁大听谁的，不会因为某一路少算了就把已有数字打回去。
//
// 例外是"五元组被复用"：同一个客户端端口重新发起连接时探针会开一条新会话，
// 累计值从 0 重来。判据是新会话的 FirstSeen 更晚且总量更小——这时候必须整体重置，
// 否则新连接的流量会被旧连接的峰值一直压住，永远算不进去。
func (a *Aggregator) IngestAbs(f *AbsFlow) {
	if a == nil || f == nil || f.SrcIP == "" || f.DstIP == "" {
		return
	}
	proto := f.Proto
	if proto == "" {
		proto = "tcp"
	}
	ft := model.FiveTuple{SrcIP: f.SrcIP, DstIP: f.DstIP, SrcPort: f.SrcPort, DstPort: f.DstPort, Proto: proto}
	key := ft.Key()
	now := a.now() // 摄入墙钟：只用于会话回收，不参与业务判定

	a.mu.Lock()
	defer a.mu.Unlock()

	st, ok := a.sessions[key]
	if !ok {
		// 容量上限与 Ingest 保持一致：先回收一轮，仍有压力就丢弃新会话。
		if a.MaxSessions > 0 && len(a.sessions) >= a.MaxSessions {
			a.evictLocked(now)
			if len(a.sessions) >= a.MaxSessions {
				a.dropped++
				return
			}
		}
		ses := &model.Session{
			FiveTuple: ft,
			MAC:       f.MAC,
			StartTTL:  f.StartTTL,
			FirstSeen: f.FirstSeen,
			LastSeen:  f.LastSeen,
			Location:  f.Location,
		}
		st = &sessionState{session: ses, dirty: true, bornAt: now, seenAt: now}
		base := st.session
		st.isClient = func(srcIP string, srcPort uint16) bool {
			return srcIP == base.FiveTuple.SrcIP && srcPort == base.FiveTuple.SrcPort
		}
		a.sessions[key] = st
	}

	ses := st.session
	st.dirty = true
	st.seenAt = now

	total := f.BytesUp + f.BytesDown
	// 五元组复用：FirstSeen 前移且总量更小 → 这是同一条四元组上的新连接。
	reused := !f.FirstSeen.IsZero() && f.FirstSeen.After(ses.FirstSeen) && total < ses.BytesUp+ses.BytesDown
	if reused {
		ses.FirstSeen = f.FirstSeen
		ses.BytesUp, ses.BytesDown, ses.Packets = 0, 0, 0
		ses.Closed = false
	}
	if total > ses.BytesUp+ses.BytesDown {
		ses.BytesUp = f.BytesUp
		ses.BytesDown = f.BytesDown
	}
	if f.Packets > ses.Packets {
		ses.Packets = f.Packets
	}
	if ses.FirstSeen.IsZero() || (!f.FirstSeen.IsZero() && f.FirstSeen.Before(ses.FirstSeen)) {
		ses.FirstSeen = f.FirstSeen
	}
	if f.LastSeen.After(ses.LastSeen) {
		ses.LastSeen = f.LastSeen
	}

	// 元数据同样只前进：探针在会话早期就解析出来的 SNI / JA3 是这条连接唯一的身份证据，
	// 后面的报文里不会再有第二次 ClientHello。
	if f.StartTTL != 0 && ses.StartTTL == 0 {
		ses.StartTTL = f.StartTTL
	}
	if ses.MAC == "" {
		ses.MAC = f.MAC
	}
	if f.DstMAC != "" {
		ses.DstMAC = f.DstMAC
	}
	if ses.Location == "" {
		ses.Location = f.Location
	}
	if f.SNI != "" && ses.SNI == "" {
		ses.SNI = f.SNI
		st.helloDone = true
	}
	if f.HTTPHost != "" && ses.HTTPHost == "" {
		ses.HTTPHost = f.HTTPHost
		st.hostDone = true
	}
	if f.JA3 != "" && ses.JA3 == "" {
		ses.JA3 = f.JA3
	}
	if f.JA4 != "" && ses.JA4 == "" {
		ses.JA4 = f.JA4
	}
	if f.UserAgent != "" && ses.UserAgent == "" {
		ses.UserAgent = f.UserAgent
		st.uaDone = true
	}
	if f.HTTPServer != "" && ses.HTTPServer == "" {
		ses.HTTPServer = f.HTTPServer
		st.srvDone = true
	}
	if f.IsLongConn {
		ses.IsLongConn = true
	}
	if f.HeartbeatIntervalMs > 0 && ses.HeartbeatIntervalMs == 0 {
		ses.HeartbeatIntervalMs = f.HeartbeatIntervalMs
	}
	if (len(f.XFF) > 0 || f.XRealIP != "") && !st.fwdDone {
		applyForwarded(ses, f.XFF, f.XRealIP)
		st.fwdDone = true
	}
	// 长连接判定与 Ingest 一致：时长够长就算，不依赖探针显式标注。
	if ses.LastSeen.Sub(ses.FirstSeen).Seconds() >= float64(a.LongConnSeconds) {
		ses.IsLongConn = true
	}
}
