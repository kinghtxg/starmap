package api

// 变更视图与趋势统计（V1.6）。
//
// 灯塔（ARL）那类产品把「变了什么」做成一级入口，原因很实际：
// 一张静态资产清单第一次看有用，第二次开始就过期了。运维真正要处置的是
// "昨天多出来的那台机器"和"上周还在的 3389 今天没了"。
// StarMap 到 1.5 只有静态视图，这里补上时间维度。

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/model"
	"starmap/internal/store"
)

const (
	changeDefaultDays = 7
	changeMaxDays     = 90
	// changeListLimit 单侧（新增/消失）最多回多少条。
	// 变更页是"看一眼今天多了什么"，不是资产清单；几千条既画不动也没人翻。
	// 超出的部分用 total 提示，引导用户收窄时间窗。
	changeListLimit = 500
)

// changeItem 变更页里的一行。
type changeItem struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	Service   string    `json:"service,omitempty"`
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	Title     string    `json:"title,omitempty"`
	TLSCN     string    `json:"tls_cn,omitempty"`
	Favicon   string    `json:"favicon_hash,omitempty"`
	NodeKey   string    `json:"node_key"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// changeGroup 一侧变更（新增 / 消失）。
type changeGroup struct {
	Total int          `json:"total"`
	Items []changeItem `json:"items"`
	// Hosts 涉及多少台不同主机。300 个新端口可能只来自 2 台机器（一台新上的
	// 业务系统），也可能来自 300 台（全网在推一个新客户端）——处置方式完全不同。
	Hosts int `json:"hosts"`
}

// listChanges 最近一段时间内新增 / 不再活动的端口。
func (s *Server) listChanges(c *gin.Context) {
	days := normalizeDays(c.Query("days"), changeDefaultDays)
	now := time.Now()
	until := now.Add(time.Minute) // 留 1 分钟余量：本轮刚写进来的行不该因为毫秒差被排除
	window := store.ChangeWindow{Since: now.AddDate(0, 0, -days), Until: until}

	added, gone, addedTotal, goneTotal, err := s.d.Store.PortChanges(window, changeListLimit)
	if err != nil {
		internalError(c, err, "读取变更失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"days":  days,
		"since": window.Since,
		"until": now,
		"added": buildChangeGroup(added, addedTotal),
		"gone":  buildChangeGroup(gone, goneTotal),
	})
}

// buildChangeGroup 组装一侧变更，含去重主机数。
func buildChangeGroup(list []model.PortRecord, total int) changeGroup {
	store.SortChangesByIP(list)
	items := make([]changeItem, 0, len(list))
	hosts := make(map[string]struct{}, len(list))
	for i := range list {
		p := &list[i]
		items = append(items, changeItem{
			IP: p.IP, Port: p.Port, Proto: p.Proto, Service: p.Service,
			Product: p.Product, Version: p.Version, Title: p.Title,
			TLSCN: p.TLSCN, Favicon: p.Favicon, NodeKey: p.NodeKey,
			State: p.State, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
		})
		hosts[p.IP] = struct{}{}
	}
	return changeGroup{Total: total, Items: items, Hosts: len(hosts)}
}

// trendStats 最近 N 天的新增资产/端口/事件。
//
// 结果缓存 60 秒：这个查询要按天扫三张表，而仪表盘会随页面停留反复刷新。
// 一分钟的陈旧度对"这周长了多少东西"完全无感，但能把重复扫描从
// "每次请求一次"降到"每分钟一次"。
func (s *Server) trendStats(c *gin.Context) {
	days := normalizeDays(c.Query("days"), changeDefaultDays)

	s.trendMu.Lock()
	if s.trendCache != nil && s.trendDays == days && time.Since(s.trendAt) < trendCacheTTL {
		cached := s.trendCache
		s.trendMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"days": days, "points": cached, "cached": true})
		return
	}
	s.trendMu.Unlock()

	points, err := s.d.Store.TrendStats(days, time.Now())
	if err != nil {
		internalError(c, err, "读取趋势失败")
		return
	}

	s.trendMu.Lock()
	s.trendCache, s.trendDays, s.trendAt = points, days, time.Now()
	s.trendMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"days": days, "points": points, "cached": false})
}

const trendCacheTTL = time.Minute

// normalizeDays 把 days 参数夹到合法范围（导出与趋势共用）。
func normalizeDays(v string, def int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	if n > changeMaxDays {
		return changeMaxDays
	}
	return n
}
