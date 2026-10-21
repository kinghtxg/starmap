// Package ledger 实现资产台账（人工登记的"应该有什么"）与拓扑观测结果
// （"实际有什么"）的对照，产出账实差异。
//
// 本包只做纯逻辑：CSV 解析 + 集合比对，不依赖存储与网络，便于单测。
//
// 四类差异：
//   - Managed    在册在网：台账有、网内也有
//   - Unmanaged  台账外设备：网内有、台账没有（影子设备，本项目核心价值）
//   - Ghost      台账僵尸：台账登记了、网内从未发现（多已下线/报废/IP 填错）
//   - IPMismatch 同机换 IP：MAC 对得上、IP 与台账不符（DHCP 变更、私自改地址）
package ledger

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"starmap/internal/model"
)

// 差异分类
const (
	KindManaged    = "managed"
	KindUnmanaged  = "unmanaged"
	KindGhost      = "ghost"
	KindIPMismatch = "ip_mismatch"
)

// Host 参与对照的主机（来自系统已发现的资产/拓扑节点，由调用方组装）。
type Host struct {
	NodeKey    string
	IPs        []string
	MAC        string
	Hostname   string
	OS         string
	Online     bool
	Department string
	Owner      string
	Location   string
	RiskLevel  string
	LastSeen   time.Time
	Archived   bool // 系统内是否已归档登记
}

// Item 一条对照结果。
type Item struct {
	Kind       string    `json:"kind"`
	IP         string    `json:"ip"`        // 观测到的 IP（Ghost 为台账 IP）
	LedgerIP   string    `json:"ledger_ip"` // 台账登记的 IP（Unmanaged 为空）
	MAC        string    `json:"mac"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	Department string    `json:"department"`
	Owner      string    `json:"owner"`
	Location   string    `json:"location"`
	NodeKey    string    `json:"node_key,omitempty"`
	Online     bool      `json:"online"`
	Archived   bool      `json:"archived"`
	RiskLevel  string    `json:"risk_level"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

// Summary 汇总
type Summary struct {
	LedgerTotal int `json:"ledger_total"`
	HostTotal   int `json:"host_total"`
	Managed     int `json:"managed"`
	Unmanaged   int `json:"unmanaged"`
	Ghost       int `json:"ghost"`
	IPMismatch  int `json:"ip_mismatch"`
}

// Result 对照结果
type Result struct {
	Summary    Summary `json:"summary"`
	Managed    []Item  `json:"managed"`
	Unmanaged  []Item  `json:"unmanaged"`
	Ghost      []Item  `json:"ghost"`
	IPMismatch []Item  `json:"ip_mismatch"`
}

// ParseStats CSV 解析统计
type ParseStats struct {
	Rows    int `json:"rows"`    // 数据行数
	Valid   int `json:"valid"`   // 有效条目
	Skipped int `json:"skipped"` // 跳过（IP 非法/空行/重复）
}

// 列名别名（全部转小写后匹配，覆盖常见台账表头写法）
var colAlias = map[string]string{
	"ip": "ip", "ip地址": "ip", "ipaddr": "ip", "ip_addr": "ip", "ipaddress": "ip", "地址": "ip",
	"mac": "mac", "mac地址": "mac", "macaddr": "mac", "物理地址": "mac",
	"hostname": "hostname", "主机名": "hostname", "设备名": "hostname", "名称": "hostname", "设备名称": "hostname",
	"os": "os", "操作系统": "os", "主机系统": "os", "系统": "os", "系统类型": "os",
	"department": "department", "dept": "department", "归属单位": "department", "单位": "department",
	"部门": "department", "归属部门": "department", "使用单位": "department",
	"owner": "owner", "归属人": "owner", "责任人": "owner", "负责人": "owner", "使用人": "owner",
	"location": "location", "位置": "location", "物理位置": "location", "机房": "location", "所在位置": "location",
	"description": "description", "备注": "description", "说明": "description", "note": "description",
}

// ParseCSV 解析台账 CSV。要求首行为表头，至少包含 IP 列（ip / IP地址 / 地址 等）。
// 容错：UTF-8 BOM、多余空格、列数不齐、字段用引号包裹、- 或 / 分隔的 MAC。
func ParseCSV(r io.Reader, batch string) ([]model.LedgerEntry, ParseStats, error) {
	var st ParseStats
	br := bufio.NewReader(r)
	// 去 UTF-8 BOM（Excel 导出常见）
	if b, err := br.Peek(3); err == nil && len(b) == 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1 // 容忍列数不齐
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true

	header, err := cr.Read()
	if err != nil {
		return nil, st, fmt.Errorf("读取表头失败：%w", err)
	}
	idx, ipCol := mapColumns(header)
	if ipCol < 0 {
		return nil, st, errors.New("未找到 IP 列，请确认表头包含 ip / IP地址 / 地址 之一")
	}

	seen := map[string]bool{}
	var out []model.LedgerEntry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 单行解析失败不整体失败，跳过计数
			st.Rows++
			st.Skipped++
			continue
		}
		if isBlankRow(rec) {
			// 空行不是数据行：不计入 Rows，否则 Rows ≠ Valid + Skipped，
			// 前端展示的"共 N 行、成功 M、跳过 K"会出现对不上的第三个数字。
			continue
		}
		st.Rows++
		ip := strings.TrimSpace(cell(rec, ipCol))
		if net.ParseIP(ip) == nil {
			st.Skipped++
			continue
		}
		if seen[ip] {
			st.Skipped++ // 台账内 IP 重复，保留首条
			continue
		}
		seen[ip] = true
		e := model.LedgerEntry{IP: ip, Batch: batch}
		if c, ok := idx["mac"]; ok {
			e.MAC = normalizeMAC(strings.TrimSpace(cell(rec, c)))
		}
		if c, ok := idx["hostname"]; ok {
			e.Hostname = strings.TrimSpace(cell(rec, c))
		}
		if c, ok := idx["os"]; ok {
			e.OS = strings.TrimSpace(cell(rec, c))
		}
		if c, ok := idx["department"]; ok {
			e.Department = strings.TrimSpace(cell(rec, c))
		}
		if c, ok := idx["owner"]; ok {
			e.Owner = strings.TrimSpace(cell(rec, c))
		}
		if c, ok := idx["location"]; ok {
			e.Location = strings.TrimSpace(cell(rec, c))
		}
		if c, ok := idx["description"]; ok {
			e.Description = strings.TrimSpace(cell(rec, c))
		}
		out = append(out, e)
	}
	st.Valid = len(out)
	if st.Valid == 0 {
		return nil, st, errors.New("没有解析出任何有效条目（IP 列可能为空或格式不对）")
	}
	return out, st, nil
}

func mapColumns(header []string) (map[string]int, int) {
	idx := map[string]int{}
	ipCol := -1
	for i, h := range header {
		k := strings.ToLower(strings.TrimSpace(h))
		k = strings.TrimPrefix(k, "\ufeff")
		k = strings.ReplaceAll(k, " ", "")
		if mapped, ok := colAlias[k]; ok {
			if _, dup := idx[mapped]; !dup {
				idx[mapped] = i
				if mapped == "ip" && ipCol < 0 {
					ipCol = i
				}
			}
		}
	}
	return idx, ipCol
}

func cell(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return rec[i]
}

func isBlankRow(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

// normalizeMAC 统一为小写、冒号分隔（Excel 里常见 AA-BB-CC 写法）。
func normalizeMAC(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")
	return strings.ToLower(strings.TrimSpace(s))
}

// Diff 对照台账与观测主机，产出四类差异。
func Diff(entries []model.LedgerEntry, hosts []Host) Result {
	res := Result{
		Managed:    []Item{},
		Unmanaged:  []Item{},
		Ghost:      []Item{},
		IPMismatch: []Item{},
	}

	byIP := make(map[string]int, len(entries))
	byMAC := make(map[string]int, len(entries))
	for i := range entries {
		byIP[entries[i].IP] = i
		if m := normalizeMAC(entries[i].MAC); m != "" {
			if _, dup := byMAC[m]; !dup { // 同 MAC 多条台账时取第一条，避免覆盖
				byMAC[m] = i
			}
		}
	}
	used := make([]bool, len(entries))

	for _, h := range hosts {
		// 1) 先按观测 IP 直接命中
		hit := -1
		for _, ip := range h.IPs {
			if i, ok := byIP[ip]; ok && !used[i] {
				hit = i
				break
			}
		}
		// 2) IP 没命中，再按 MAC 命中（同机换 IP）
		macHit, macMatched := -1, false
		if hit < 0 {
			if m := normalizeMAC(h.MAC); m != "" {
				if i, ok := byMAC[m]; ok && !used[i] {
					macHit, macMatched = i, true
				}
			}
		}

		switch {
		case hit >= 0:
			used[hit] = true
			res.Managed = append(res.Managed, item(KindManaged, h, &entries[hit], primaryIP(h)))
		case macMatched && macHit >= 0:
			used[macHit] = true
			res.IPMismatch = append(res.IPMismatch, item(KindIPMismatch, h, &entries[macHit], primaryIP(h)))
		default:
			res.Unmanaged = append(res.Unmanaged, item(KindUnmanaged, h, nil, primaryIP(h)))
		}
	}

	for i := range entries {
		if used[i] {
			continue
		}
		e := &entries[i]
		res.Ghost = append(res.Ghost, Item{
			Kind:       KindGhost,
			IP:         e.IP,
			LedgerIP:   e.IP,
			MAC:        e.MAC,
			Hostname:   e.Hostname,
			OS:         e.OS,
			Department: e.Department,
			Owner:      e.Owner,
			Location:   e.Location,
		})
	}

	sortItems(res.Managed)
	sortItems(res.Unmanaged)
	sortItems(res.Ghost)
	sortItems(res.IPMismatch)
	res.Summary = Summary{
		LedgerTotal: len(entries),
		HostTotal:   len(hosts),
		Managed:     len(res.Managed),
		Unmanaged:   len(res.Unmanaged),
		Ghost:       len(res.Ghost),
		IPMismatch:  len(res.IPMismatch),
	}
	return res
}

// item 组装单条结果：台账信息优先（人工登记更权威），缺失字段回落到观测值。
func item(kind string, h Host, e *model.LedgerEntry, ip string) Item {
	it := Item{
		Kind:      kind,
		IP:        ip,
		MAC:       h.MAC,
		Hostname:  h.Hostname,
		OS:        h.OS,
		NodeKey:   h.NodeKey,
		Online:    h.Online,
		Archived:  h.Archived,
		RiskLevel: h.RiskLevel,
		LastSeen:  h.LastSeen,
	}
	if e != nil {
		it.LedgerIP = e.IP
		if e.MAC != "" {
			it.MAC = e.MAC
		}
		if it.Hostname == "" {
			it.Hostname = e.Hostname
		}
		if it.OS == "" {
			it.OS = e.OS
		}
		it.Department = e.Department
		it.Owner = e.Owner
		it.Location = e.Location
	}
	if it.Department == "" {
		it.Department = h.Department
	}
	if it.Owner == "" {
		it.Owner = h.Owner
	}
	if it.Location == "" {
		it.Location = h.Location
	}
	return it
}

func primaryIP(h Host) string {
	if len(h.IPs) > 0 {
		return h.IPs[0]
	}
	return ""
}

func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		// 风险高的排前面，其次按 IP
		if ra, rb := riskRank(a.RiskLevel), riskRank(b.RiskLevel); ra != rb {
			return ra > rb
		}
		return ipLess(a.IP, b.IP)
	})
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

// ipLess 按 IPv4 数值排序（纯字符串排序会把 10.0.0.10 排到 10.0.0.9 前面）。
func ipLess(a, b string) bool {
	return ipKey(a) < ipKey(b)
}

func ipKey(ip string) string {
	return fmt.Sprintf("%03d.%03d.%03d.%03d", octet(ip, 0), octet(ip, 1), octet(ip, 2), octet(ip, 3))
}

func octet(ip string, i int) int {
	p := net.ParseIP(ip).To4()
	if p == nil || i > 3 {
		return 0
	}
	return int(p[i])
}
