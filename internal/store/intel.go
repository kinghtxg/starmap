package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"starmap/internal/model"
)

// 本地情报库（V1.5）。
//
// 设计要点，都是踩过点才这么写的：
//
//  1. **以 indicator 为主键**，不做 append-only。情报是"当前结论"，不是流水账：
//     同一个 IP 今天 black、明天 white 很正常，留一堆历史版本只会让"现在到底是不是坏"变模糊。
//  2. **latest-wins，且旧版本不能覆盖新版本**。推送方重试、乱序、补发全量都是常态，
//     如果无条件覆盖，一次迟到的旧包就能把新情报洗回旧结论，而且是静默的。
//     判新旧：版本号优先，其次数据时间（updated_at）。
//  3. **分批事务**。库用的是单连接（SetMaxOpenConns(1)），一次性写几十万条会把
//     事件写入、配置读取全部堵死。每 chunk 提交一次，中间让出连接。
//  4. **区分 stale / unchanged / updated**。推送方只看到 "200 OK" 会以为全生效了，
//     实际可能一条都没进库（时钟偏差、重放）。统计必须能说清"为什么没生效"。

const intelChunk = 400 // 单次 IN(...) 与单事务的批大小：兼顾 SQLite 变量上限与锁占用时长

// NormalizeIndicator 规范化情报指标，返回 (indicator, kind, ok)。
//
// 为什么要规范化：情报平台发来的可能是 "1.2.3.4 "（尾空格）、"1.2.3.4/32"、
// "2001:DB8::1"（大写）、"Evil.COM"（大小写混杂）。不统一，同一个地址会变成
// 七八个主键，查的时候永远命不中。
func NormalizeIndicator(v string) (string, string, bool) {
	s := strings.TrimSpace(v)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 {
		return "", "", false
	}
	// IP
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), "ip", true
		}
		return ip.String(), "ip", true
	}
	// CIDR：保留掩码（网段情报是有效的，/32 归一成单 IP）
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return "", "", false
		}
		if ones, bits := ipnet.Mask.Size(); bits == 32 && ones == 32 {
			return ipnet.IP.String(), "ip", true
		} else if bits == 128 && ones == 128 {
			return ipnet.IP.String(), "ip", true
		}
		return ipnet.String(), "cidr", true
	}
	// 域名：只做保守校验，不做 DNS
	if strings.Contains(s, ".") && len(s) <= 253 {
		// 纯数字点分但 ParseIP 失败，说明是残缺 IPv4（"1.2.3"、"1.2.3.4.5"、超范围）。
		// 不能放行成域名：那会造出一个永远命不中真实流量的幽灵记录，
		// 而且推送方会以为"这条已经进库了"。
		numeric := true
		for _, r := range s {
			if r != '.' && (r < '0' || r > '9') {
				numeric = false
				break
			}
		}
		if numeric {
			return "", "", false
		}
		for _, r := range s {
			if !(r == '.' || r == '-' || r == '_' ||
				(r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				if r >= 'A' && r <= 'Z' {
					continue
				}
				return "", "", false
			}
		}
		return strings.ToLower(s), "domain", true
	}
	return "", "", false
}

// intelNewer 判断来件是否比库里的更新。ver 优先（单调递增），否则比数据时间。
// 相等视为"同版本"，调用方按 unchanged 处理，不做写入。
func intelNewer(in model.IntelRecord, cur model.IntelRecord) bool {
	if in.Version != cur.Version {
		return in.Version > cur.Version
	}
	return in.UpdatedAt.After(cur.UpdatedAt)
}

func encodeIntelTags(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	// 标签来自外部数据：限长 + 去重 + 截断，避免一条脏数据把整行 JSON 撑爆
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if len(t) > 40 {
			t = t[:40]
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 20 {
			break
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func decodeIntelTags(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// UpsertIntelBatch 批量写入/覆盖情报记录，返回逐项统计。
//
// 单条记录非法（地址格式错）只计入 Invalid，不中断整批——
// 情报推送里混着几条脏数据是常态，为它整批失败等于让运维无从下手。
func (s *Store) UpsertIntelBatch(recs []model.IntelRecord) (model.IntelIngestStat, error) {
	var st model.IntelIngestStat
	st.Received = len(recs)
	if len(recs) == 0 {
		return st, nil
	}
	now := time.Now().UTC()

	// 先规范化 + 按 indicator 去重（同一批里重复的取版本新的那条）
	byKey := make(map[string]model.IntelRecord, len(recs))
	order := make([]string, 0, len(recs))
	for _, r := range recs {
		ind, kind, ok := NormalizeIndicator(r.Indicator)
		if !ok {
			st.Invalid++
			continue
		}
		r.Indicator, r.Kind = ind, kind
		if r.Verdict == "" {
			r.Verdict = "unknown"
		}
		if r.UpdatedAt.IsZero() {
			// 推送方没给数据时间：按到达时间算，语义是"这条是最新的"
			r.UpdatedAt = now
		} else {
			r.UpdatedAt = r.UpdatedAt.UTC()
		}
		if r.Score < 0 {
			r.Score = 0
		} else if r.Score > 100 {
			r.Score = 100
		}
		if r.ReceivedAt.IsZero() {
			r.ReceivedAt = now
		}
		if old, ok := byKey[ind]; ok {
			if !intelNewer(r, old) {
				continue
			}
		} else {
			order = append(order, ind)
		}
		byKey[ind] = r
	}

	// 分块：先读存量判新旧，再在同一个事务里写，统计才准确
	for start := 0; start < len(order); start += intelChunk {
		end := start + intelChunk
		if end > len(order) {
			end = len(order)
		}
		chunk := order[start:end]

		cur, err := s.intelExisting(chunk)
		if err != nil {
			return st, err
		}

		tx, err := s.db.Begin()
		if err != nil {
			return st, err
		}
		stmt, err := tx.Prepare(`INSERT INTO intel_iocs
			(indicator,kind,verdict,score,tags,source,intel_ver,updated_at,received_at,expires_at,raw)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(indicator) DO UPDATE SET
				kind=excluded.kind, verdict=excluded.verdict, score=excluded.score,
				tags=excluded.tags,
				-- 来源是溯源信息：来件没声明时保留库里已知的来源，
				-- 不能被一次"没写 source"的增量推送抹成空白
				source=CASE WHEN excluded.source='' THEN intel_iocs.source ELSE excluded.source END,
				intel_ver=excluded.intel_ver,
				updated_at=excluded.updated_at, received_at=excluded.received_at,
				expires_at=excluded.expires_at, raw=excluded.raw
			WHERE excluded.intel_ver > intel_iocs.intel_ver
			   OR (excluded.intel_ver = intel_iocs.intel_ver
			       AND excluded.updated_at >= intel_iocs.updated_at)`)
		if err != nil {
			tx.Rollback()
			return st, err
		}

		for _, ind := range chunk {
			r := byKey[ind]
			old, exists := cur[ind]
			if exists {
				if r.Version == old.Version && r.UpdatedAt.Equal(old.UpdatedAt) {
					if r.Verdict == old.Verdict && r.Score == old.Score {
						st.Unchanged++
						continue
					}
					// 同一个 (version, updated_at) 声称了两种不同结论。
					// 谁对无法判断，但"改变已发布的判定"必须留痕——升版本号再来。
					// 若在这里放行，"先推恶意再推干净"就成了无声的洗白，
					// 而且事后无法从库里看出哪一次是对的。
					st.Conflict++
					continue
				}
				if !intelNewer(r, old) {
					st.Stale++
					continue
				}
			}
			var exp any
			if r.ExpiresAt != nil {
				exp = r.ExpiresAt.UTC()
			}
			if _, err := stmt.Exec(r.Indicator, r.Kind, r.Verdict, r.Score,
				encodeIntelTags(r.Tags), r.Source, r.Version,
				r.UpdatedAt, r.ReceivedAt, exp, truncate(r.Raw, 512)); err != nil {
				stmt.Close()
				tx.Rollback()
				return st, fmt.Errorf("写入情报 %s 失败: %w", ind, err)
			}
			if exists {
				st.Updated++
			} else {
				st.Inserted++
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return st, err
		}
	}
	return st, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// intelExisting 一次取回这批 indicator 的存量记录。
func (s *Store) intelExisting(indicators []string) (map[string]model.IntelRecord, error) {
	out := make(map[string]model.IntelRecord, len(indicators))
	if len(indicators) == 0 {
		return out, nil
	}
	ph := make([]string, len(indicators))
	args := make([]any, len(indicators))
	for i, k := range indicators {
		ph[i] = "?"
		args[i] = k
	}
	rows, err := s.db.Query(`SELECT indicator,kind,verdict,score,tags,source,intel_ver,
		updated_at,received_at,expires_at,raw FROM intel_iocs WHERE indicator IN (`+
		strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r model.IntelRecord
		var tags string
		var exp sql.NullTime
		if err := rows.Scan(&r.Indicator, &r.Kind, &r.Verdict, &r.Score, &tags,
			&r.Source, &r.Version, &r.UpdatedAt, &r.ReceivedAt, &exp, &r.Raw); err != nil {
			return nil, err
		}
		r.Tags = decodeIntelTags(tags)
		if exp.Valid {
			t := exp.Time
			r.ExpiresAt = &t
		}
		out[r.Indicator] = r
	}
	return out, rows.Err()
}

// LookupIntel 按 indicator 查一条本地情报。命中返回记录，未命中返回 nil。
func (s *Store) LookupIntel(indicator string) (*model.IntelRecord, error) {
	ind, _, ok := NormalizeIndicator(indicator)
	if !ok {
		return nil, nil
	}
	m, err := s.intelExisting([]string{ind})
	if err != nil {
		return nil, err
	}
	if r, ok := m[ind]; ok {
		return &r, nil
	}
	return nil, nil
}

// LookupIntelBatch 批量查（拓扑出图时一次搞定，不逐节点查库）。
func (s *Store) LookupIntelBatch(indicators []string) (map[string]model.IntelRecord, error) {
	uniq := make([]string, 0, len(indicators))
	seen := map[string]bool{}
	for _, v := range indicators {
		ind, _, ok := NormalizeIndicator(v)
		if !ok || seen[ind] {
			continue
		}
		seen[ind] = true
		uniq = append(uniq, ind)
	}
	out := make(map[string]model.IntelRecord, len(uniq))
	for start := 0; start < len(uniq); start += intelChunk {
		end := start + intelChunk
		if end > len(uniq) {
			end = len(uniq)
		}
		m, err := s.intelExisting(uniq[start:end])
		if err != nil {
			return out, err
		}
		for k, v := range m {
			out[k] = v
		}
	}
	return out, nil
}

// IntelStats 本地库概况：条数、各判定分布、最后入库时间、最早过期时间。
// 前端要能回答"我的情报库有多大、多久没更新了"——库是空的还是没接上，看这个一眼就懂。
func (s *Store) IntelStats() (map[string]any, error) {
	out := map[string]any{"total": 0, "by_verdict": map[string]int{}, "sources": map[string]int{}}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM intel_iocs`).Scan(&total); err != nil {
		return out, err
	}
	out["total"] = total

	rows, err := s.db.Query(`SELECT verdict, COUNT(*) FROM intel_iocs GROUP BY verdict`)
	if err != nil {
		return out, err
	}
	byVerdict := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			rows.Close()
			return out, err
		}
		byVerdict[v] = n
	}
	rows.Close()
	out["by_verdict"] = byVerdict

	rows, err = s.db.Query(`SELECT source, COUNT(*) FROM intel_iocs GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10`)
	if err != nil {
		return out, err
	}
	sources := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			rows.Close()
			return out, err
		}
		if v == "" {
			v = "(未标注)"
		}
		sources[v] = n
	}
	rows.Close()
	out["sources"] = sources

	// 时间字段用 ORDER BY + LIMIT 1 取，而不是 MAX()/MIN()：
	// 聚合函数会把 DATETIME 列变成无类型表达式，驱动拿不到列类型时无法
	// 扫描进 time.Time，MAX() 那条会静默失败 —— 界面上的"最后入库"永远是 "-"。
	var last, oldest time.Time
	if err := s.db.QueryRow(
		`SELECT received_at FROM intel_iocs ORDER BY received_at DESC LIMIT 1`).Scan(&last); err == nil {
		out["last_received_at"] = last.UTC().Format(time.RFC3339)
	}
	if err := s.db.QueryRow(
		`SELECT updated_at FROM intel_iocs ORDER BY updated_at ASC LIMIT 1`).Scan(&oldest); err == nil {
		out["oldest_updated_at"] = oldest.UTC().Format(time.RFC3339)
	}
	return out, nil
}

// PruneIntel 清理超过保留期的情报。
//
// 为什么必须有：情报是会过期的结论。一条 90 天前的 malicious 如果一直留在库里，
// 那台机器会永远标红，而这个红点已经不代表任何风险——最后的结果是用户不再相信红色。
// days<=0 表示不清理（默认由配置决定）。
func (s *Store) PruneIntel(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cut := time.Now().UTC().AddDate(0, 0, -days)
	res, err := s.db.Exec(`DELETE FROM intel_iocs WHERE updated_at < ?`, cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteIntel 删除单条（人工纠错用）。
func (s *Store) DeleteIntel(indicator string) error {
	ind, _, ok := NormalizeIndicator(indicator)
	if !ok {
		return fmt.Errorf("非法情报指标: %s", indicator)
	}
	_, err := s.db.Exec(`DELETE FROM intel_iocs WHERE indicator=?`, ind)
	return err
}

// ListIntel 分页列出（管理页排查用），按数据时间倒序。
func (s *Store) ListIntel(verdict string, limit, offset int) ([]model.IntelRecord, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where, args := "", []any{}
	if verdict != "" {
		where = " WHERE verdict=?"
		args = append(args, verdict)
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM intel_iocs`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT indicator,kind,verdict,score,tags,source,intel_ver,
		updated_at,received_at,expires_at,raw FROM intel_iocs`+where+
		` ORDER BY updated_at DESC, indicator LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.IntelRecord
	for rows.Next() {
		var r model.IntelRecord
		var tags string
		var exp sql.NullTime
		if err := rows.Scan(&r.Indicator, &r.Kind, &r.Verdict, &r.Score, &tags,
			&r.Source, &r.Version, &r.UpdatedAt, &r.ReceivedAt, &exp, &r.Raw); err != nil {
			return nil, 0, err
		}
		r.Tags = decodeIntelTags(tags)
		if exp.Valid {
			t := exp.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
