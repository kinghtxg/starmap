// Package model 定义 StarMap 星图 V1.0 的全部核心数据结构。
// JSON tag 即 REST API 字段，见 SPEC §3。
package model

import (
	"time"

	"starmap/internal/auth"
)

// 风险等级
const (
	RiskNone = "none"
	RiskLow  = "low"
	RiskMid  = "mid"
	RiskHigh = "high"
)

// 风险事件类型
const (
	EventTypeFRP           = "frp"
	EventTypeClash         = "clash"
	EventTypeReverseProxy  = "reverse_proxy"
	EventTypeUnknownEgress = "unknown_egress"
	EventTypeMultiNet      = "multi_net"
)

// 风险事件状态
const (
	EventStatusPending       = "pending"
	EventStatusConfirmed     = "confirmed"
	EventStatusFalsePositive = "false_positive"
	EventStatusDeferred      = "deferred"
)

// Node 拓扑节点
type Node struct {
	ID int64 `json:"id"`
	// NodeKey 跨进程重启稳定的节点身份：优先 MAC（mac:<mac>），无 MAC 用主 IP（ip:<ip>），
	// 外部聚合节点为 ext:<cidr>。一经确定不再变更，用作拓扑持久化主键与白名单 node 维度取值，
	// 修复 P0-2（重启后 node_id 重排导致历史事件变孤儿、白名单 node 维度错配静默抑制）。
	NodeKey   string    `json:"node_key"`
	IPs       []string  `json:"ips"`
	MAC       string    `json:"mac"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Domain    string    `json:"domain"` // 网络域，见 NetDomain
	Labels    []string  `json:"labels"`
	RiskLevel string    `json:"risk_level"` // none|low|mid|high
	Active    bool      `json:"active"`
	// Location 归属位置（探针上报时携带，用于按探针位置自动归纳拓扑，V1.3）。
	Location string `json:"location,omitempty"`
}

// Edge 拓扑链路
type Edge struct {
	ID        int64     `json:"id"`
	SrcID     int64     `json:"src_id"`
	DstID     int64     `json:"dst_id"`
	Protocol  string    `json:"protocol"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Active    bool      `json:"active"`
}

// TopoStats 拓扑统计
type TopoStats struct {
	NodeCount   int   `json:"node_count"`
	EdgeCount   int   `json:"edge_count"`
	ActiveNodes int   `json:"active_nodes"`
	ActiveEdges int   `json:"active_edges"`
	TotalBytes  int64 `json:"total_bytes"`
}

// TopoSnapshot GET /api/topology 的返回体
type TopoSnapshot struct {
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
	Stats       TopoStats `json:"stats"`
	GeneratedAt time.Time `json:"generated_at"`
}

// FiveTuple 五元组
type FiveTuple struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   string `json:"proto"` // tcp|udp
}

// Key 返回归一化（双向去重）的五元组 key，用于会话聚合。
func (t FiveTuple) Key() string {
	a := t.SrcIP + ":" + itoa(int(t.SrcPort))
	b := t.DstIP + ":" + itoa(int(t.DstPort))
	if a > b {
		a, b = b, a
	}
	return t.Proto + "|" + a + "|" + b
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}

// Session 会话（内存聚合结果，可持久化）
type Session struct {
	FiveTuple           FiveTuple `json:"five_tuple"`
	MAC                 string    `json:"mac"`
	DstMAC              string    `json:"dst_mac,omitempty"` // 客户端方向目的 MAC（首跳网关推断用）
	StartTTL            int       `json:"start_ttl"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
	BytesUp             int64     `json:"bytes_up"`
	BytesDown           int64     `json:"bytes_down"`
	Packets             int64     `json:"packets"`
	SNI                 string    `json:"sni,omitempty"`
	HTTPHost            string    `json:"http_host,omitempty"`
	JA3                 string    `json:"ja3,omitempty"`
	JA4                 string    `json:"ja4,omitempty"`
	IsLongConn          bool      `json:"is_long_conn"`
	HeartbeatIntervalMs int64     `json:"heartbeat_interval_ms,omitempty"`
	Closed              bool      `json:"closed"`
	// Location 来源探针的位置（用于按探针位置归纳拓扑，V1.3）；ProbeID 为来源探针标识。
	Location string `json:"location,omitempty"`
	ProbeID  string `json:"probe_id,omitempty"`
}

// RiskEvent 风险事件
type RiskEvent struct {
	ID         int64             `json:"id"`
	Type       string            `json:"type"` // frp|clash|reverse_proxy|unknown_egress|multi_net
	NodeID     int64             `json:"node_id"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail"`
	Evidence   map[string]string `json:"evidence"`
	Status     string            `json:"status"` // pending|confirmed|false_positive|deferred
	Level      string            `json:"level"`  // mid|high
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	ReviewNote string            `json:"review_note,omitempty"`
	Reviewer   string            `json:"reviewer,omitempty"`
}

// WhitelistEntry 白名单条目
type WhitelistEntry struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"` // cidr|ip|host|node
	Value     string    `json:"value"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// NetDomain 网络域（gov|office|internet|prod|自定义）
type NetDomain struct {
	ID    int64    `json:"id"`
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
	Color string   `json:"color"`
}

// AuditLog 审计日志
type AuditLog struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// SystemConfig 系统参数（探测开关、抓包网卡、老化时长、聚合阈值等）
type SystemConfig struct {
	ProbeEnabled       bool     `json:"probe_enabled" yaml:"probe_enabled"`
	CaptureEnabled     bool     `json:"capture_enabled" yaml:"capture_enabled"`
	CaptureInterfaces  []string `json:"capture_interfaces" yaml:"capture_interfaces"`
	CaptureBPF         string   `json:"capture_bpf" yaml:"capture_bpf"`
	AgingSeconds       int64    `json:"aging_seconds" yaml:"aging_seconds"`
	AggregateThreshold int      `json:"aggregate_threshold" yaml:"aggregate_threshold"`
	NoiseBytes         int64    `json:"noise_bytes" yaml:"noise_bytes"`
	NoisePackets       int64    `json:"noise_packets" yaml:"noise_packets"`
	NoiseDurationSec   int64    `json:"noise_duration_sec" yaml:"noise_duration_sec"`
	ReverseProxyHosts  int      `json:"reverse_proxy_hosts" yaml:"reverse_proxy_hosts"`
	LongConnSeconds    int64    `json:"long_conn_seconds" yaml:"long_conn_seconds"`
	HeartbeatMaxBytes  int      `json:"heartbeat_max_bytes" yaml:"heartbeat_max_bytes"`
	ListenAddr         string   `json:"listen_addr" yaml:"listen_addr"`
	DBPath             string   `json:"db_path" yaml:"db_path"`
	ProbeToken         string   `json:"probe_token" yaml:"probe_token"`                   // §10.7 探针上报可选 token
	AuditRetentionDays int      `json:"audit_retention_days" yaml:"audit_retention_days"` // §10.8 审计日志保留天数
	// P0-4：CORS 白名单。为空表示仅允许同源（不发 Access-Control-Allow-Origin）。
	CorsOrigins []string `json:"cors_origins" yaml:"cors_origins"`
	// 可选账号系统 / APSSO SSO 门卫，默认 mode=none 即不启用（合规裁定 K1，见 docs/AUTH-APSSO.md）。
	Auth auth.Config `json:"auth" yaml:"auth"`
	// 未归档主机离线自动清理阈值（小时，默认 72）。0 表示不清理。
	UnarchivedOfflineHours int `json:"unarchived_offline_hours" yaml:"unarchived_offline_hours"`
	// 归档主机离线判定阈值（秒，默认 600）。last_seen 超该值即标记 offline。
	ArchiveOfflineSeconds int64 `json:"archive_offline_seconds" yaml:"archive_offline_seconds"`
	// nmap 可执行文件路径（主动端口扫描，默认 "nmap"）。留空或不可用则禁用。
	NmapPath string `json:"-" yaml:"nmap_path"`
	// 主动端口扫描的端口范围（nmap -p 参数），默认 "1-65535"（全端口）。后台可配。
	ScanPorts string `json:"scan_ports" yaml:"scan_ports"`
	// 扫描速率模板（nmap -T0~-T5），默认 "T4"。
	ScanRate string `json:"scan_rate" yaml:"scan_rate"`
}

// ---------- 主机资产库（V1.2） ----------

// 资产状态
const (
	AssetUnarchived = "unarchived" // 未归档（系统自动发现，尚未人工登记）
	AssetArchived   = "archived"   // 已归档（已登记归属单位/人/系统等）
)

// Asset 主机资产：通过 NodeKey 关联拓扑节点。
type Asset struct {
	ID          int64     `json:"id"`
	NodeKey     string    `json:"node_key"`
	IPs         []string  `json:"ips"`
	MAC         string    `json:"mac"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`          // 主机系统（如 Windows Server 2022 / Ubuntu 22.04）
	Status      string    `json:"status"`      // unarchived | archived
	Owner       string    `json:"owner"`       // 归属人
	Department  string    `json:"department"`  // 归属单位
	Location    string    `json:"location"`    // 物理位置
	Description string    `json:"description"` // 备注
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Online      bool      `json:"online"` // 是否在线（last_seen 在阈值内）
	ArchivedAt  time.Time `json:"archived_at,omitempty"`
	ArchivedBy  string    `json:"archived_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ---------- 端口记录（V1.2） ----------

// 端口记录来源
const (
	PortSourceTraffic = "traffic" // 从流量会话五元组提取
	PortSourceProbe   = "probe"   // 主动探测（nmap）
	PortSourceARP     = "arp"     // ARP 探测（无端口，占位保留）
)

// PortRecord 主机端口记录。
type PortRecord struct {
	ID        int64     `json:"id"`
	NodeKey   string    `json:"node_key"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`   // tcp | udp
	Service   string    `json:"service"` // 服务名（nmap 识别）
	State     string    `json:"state"`   // open | closed | filtered
	Source    string    `json:"source"`  // traffic | probe | arp
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Probe 远端探针注册（V1.3：按探针位置自动归纳拓扑）。
type Probe struct {
	ProbeID   string    `json:"probe_id"`
	Name      string    `json:"name"`
	Location  string    `json:"location"` // 探针部署位置（机房/分支/网段）
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}
