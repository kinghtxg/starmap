package store

// 变更视图与趋势统计（V1.6）。
//
// 这两件事在灯塔那类资产测绘产品里是高频入口，而 StarMap 到 1.5 为止只有
// "当前长什么样"的静态视图，没有任何"跟上周比变了什么"的视角。
// 对"理清网内结构"这个定位来说，静态清单会用一次就过期：
// 真正值得处置的是**新长出来的**和**悄悄消失的**。
//
// 实现上不引入快照表，全部由 ports 表现有的 first_seen / last_seen 推导：
//   - 新增 = 窗口内 first_seen 落了进来
//   - 消失 = 窗口内 last_seen 没再刷新（说明它不再活动）
// 再存一份"每次扫描的快照"会让两处数据开始漂移，而漂移从来不会自愈。

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"starmap/internal/model"
)

// dayExpr 从 DATETIME 列取日期前缀。
//
// 必须用 substr 而不是 date()：驱动把 time.Time 绑成 RFC3339（带 'T'），
// SQLite 的 date() 只认空格分隔，会静默返回 NULL——所有行落进同一个 NULL 桶，
// 趋势图变成一条平线而接口仍然 200。见 timefmt_test.go。
func dayExpr(col string) string { return `substr(` + col + `,1,10)` }

// ChangeWindow 变更视图的时间窗口。
type ChangeWindow struct {
	Since time.Time
	Until time.Time
}

// PortChanges 窗口内新增 / 不再活动的端口。
//
// added：窗口内第一次被观测到（first_seen ∈ [since, until)）。
// gone：窗口内没有再次被观测到（last_seen < since），且不是窗口内新出现的
// （first_seen < since，否则一条"出现又马上没了"的记录会同时算进两边）。
//
// 状态为 stale 的端口仍然进 gone：它们本来就是"确定已消失"的那一档，
// 正是用户想看的。反向不成立——stale 的端口不可能进 added。
func (s *Store) PortChanges(w ChangeWindow, limit int) (added, gone []model.PortRecord, addedTotal, goneTotal int, err error) {
	addedWhere := `first_seen >= ? AND first_seen < ?`
	goneWhere := `last_seen < ? AND first_seen < ?`
	args := []any{w.Since, w.Until}

	if err = s.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE `+addedWhere, args...).Scan(&addedTotal); err != nil {
		return nil, nil, 0, 0, err
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE `+goneWhere, args...).Scan(&goneTotal); err != nil {
		return nil, nil, 0, 0, err
	}

	// 新增按 first_seen 倒序（最新的在最上面），消失按 last_seen 倒序
	// （最近还活着、刚刚掉线的排前面，比"三年前开过"更值得看）。
	q1, a1 := applyPage(portColumns+` WHERE `+addedWhere+` ORDER BY first_seen DESC, id DESC`, args, limit, 0)
	if added, err = s.queryPorts(q1, a1); err != nil {
		return nil, nil, 0, 0, err
	}
	q2, a2 := applyPage(portColumns+` WHERE `+goneWhere+` ORDER BY last_seen DESC, id DESC`, args, limit, 0)
	if gone, err = s.queryPorts(q2, a2); err != nil {
		return nil, nil, 0, 0, err
	}
	return added, gone, addedTotal, goneTotal, nil
}

// queryPorts 执行一条返回端口列的结果集。
func (s *Store) queryPorts(q string, args []any) ([]model.PortRecord, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.PortRecord, 0, 32)
	for rows.Next() {
		p, err := scanPort(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// TrendStats 最近 days 天的新增资产 / 端口 / 事件，按天对齐。
//
// 返回的序列**长度恒等于 days**，没有数据的那天补 0：
// 前端折线图按数组下标画 X 轴，缺一天就会把后面的点整体左移一格，
// 看起来像"这天数据丢了"。
func (s *Store) TrendStats(days int, now time.Time) ([]model.TrendPoint, error) {
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90 // 90 天以上按天画没人看得清，也撑不住全表扫
	}
	// 从 days-1 天前的那一天零点起算，保证最后一天是"今天"。
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := today.AddDate(0, 0, -days+1)
	since := start.Format("2006-01-02")

	buckets := make(map[string]*model.TrendPoint, days)
	out := make([]model.TrendPoint, days)
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i).Format("2006-01-02")
		out[i] = model.TrendPoint{Date: d}
		buckets[d] = &out[i]
	}

	type series struct {
		sql  string
		put  func(p *model.TrendPoint, n int)
		desc string
	}
	list := []series{
		{
			sql: `SELECT ` + dayExpr("created_at") + ` d, COUNT(*) FROM assets
			      WHERE created_at >= ? GROUP BY d`,
			put:  func(p *model.TrendPoint, n int) { p.Assets = n },
			desc: "资产",
		},
		{
			sql: `SELECT ` + dayExpr("first_seen") + ` d, COUNT(*) FROM ports
			      WHERE first_seen >= ? GROUP BY d`,
			put:  func(p *model.TrendPoint, n int) { p.Ports = n },
			desc: "端口",
		},
		{
			sql: `SELECT ` + dayExpr("created_at") + ` d, COUNT(*) FROM events
			      WHERE created_at >= ? GROUP BY d`,
			put:  func(p *model.TrendPoint, n int) { p.Events = n },
			desc: "事件",
		},
	}

	for _, sr := range list {
		rows, err := s.db.Query(sr.sql, since)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var day string
			var n int
			if err := rows.Scan(&day, &n); err != nil {
				rows.Close()
				return nil, err
			}
			// 库里可能出现"未来"的行（时钟回拨、导入历史 PCAP），
			// 落在序列之外就丢弃，不要往最后一天上累加。
			if p, ok := buckets[strings.TrimSpace(day)]; ok {
				sr.put(p, n)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// SortChangesByIP 按 IP 数值序 + 端口排序（前端展示与 CSV 导出共用）。
//
// 字符串序会把 10.0.0.10 排在 10.0.0.2 前面，运维扫一眼就会觉得"乱"。
// 用 netip 而不是手写点分解析：IPv6、前导零、带端口这些形态手写必出错，
// 而这段代码只负责排序，出错时表现为"顺序微妙地不对"，没人会去查。
func SortChangesByIP(list []model.PortRecord) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		ai, err1 := netip.ParseAddr(a.IP)
		bi, err2 := netip.ParseAddr(b.IP)
		if err1 == nil && err2 == nil && ai != bi {
			return ai.Less(bi)
		}
		if err1 != nil || err2 != nil {
			if c := strings.Compare(a.IP, b.IP); c != 0 {
				return c < 0
			}
		}
		return a.Port < b.Port
	})
}
