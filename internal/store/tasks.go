package store

// 主动发现任务账（V1.6）。
//
// 设计取舍：
//   - **只记任务账，不记扫描结果**。端口/指纹在 ports 表里已经有了，再存一份
//     就得处理"两边不一致时谁对"，而这种不一致从来不会自己消失。
//   - 目标列表用换行拼成一个 TEXT 存。IP/CIDR 里不会有换行，比 JSON 省事，
//     人直接 psql 看也读得懂。
//   - 更新只发生在开始与结束两个时刻。扫描过程中每台主机都写一次库，
//     在 /24 × 65535 端口这种量级下会把 SQLite 的单写者锁打满，
//     进度由内存态提供（`/api/discover/status/:id` 已经是这么做的）。

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"starmap/internal/model"
)

const taskColumns = `id, targets, profile, profile_label, status, total, done, alive,
	open_ports, fingerprints, error, created_by, started_at, finished_at`

func splitTargets(targets []string) string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

// ParseTargets 把库里的换行分隔目标还原成切片（导出给 API 层复用）。
func ParseTargets(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';' || r == ' ' || r == '\t'
	})
}

// StartDiscoverTask 记录任务开始。
func (s *Store) StartDiscoverTask(t model.DiscoverTask) error {
	_, err := s.db.Exec(`INSERT INTO discover_tasks
		(id, targets, profile, profile_label, status, total, done, alive, open_ports,
		 fingerprints, error, created_by, started_at, finished_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
		t.ID, splitTargets(t.Targets), t.Profile, t.ProfileLabel, t.Status,
		t.Total, t.Done, t.Alive, t.OpenPorts, t.Fingerprints, t.Error, t.CreatedBy,
		t.StartedAt)
	return err
}

// FinishDiscoverTask 记录任务结束（正常/报错/被取消都走这里）。
//
// 用 `WHERE id=?` 覆盖写而不是先查再改：进程重启后重新接管一个"running"任务
// 的场景下先查会读到旧值，直接覆盖写才是幂等的。
func (s *Store) FinishDiscoverTask(t model.DiscoverTask) error {
	if t.Status == "" {
		return errors.New("任务结束状态不能为空")
	}
	res, err := s.db.Exec(`UPDATE discover_tasks SET
		status=?, total=?, done=?, alive=?, open_ports=?, fingerprints=?, error=?, finished_at=?
		WHERE id=?`,
		t.Status, t.Total, t.Done, t.Alive, t.OpenPorts, t.Fingerprints, t.Error,
		t.FinishedAt, t.ID)
	if err != nil {
		return err
	}
	// 任务只存在于内存（例如进程刚重启、库里还没写）时，这里补一条，
	// 否则这次扫描在历史里彻底消失——比记错一条更糟。
	if n, _ := res.RowsAffected(); n == 0 {
		return s.StartDiscoverTask(t)
	}
	return nil
}

func scanDiscoverTask(sc interface{ Scan(...any) error }) (model.DiscoverTask, error) {
	var t model.DiscoverTask
	var targets string
	var finished sql.NullTime
	err := sc.Scan(&t.ID, &targets, &t.Profile, &t.ProfileLabel, &t.Status,
		&t.Total, &t.Done, &t.Alive, &t.OpenPorts, &t.Fingerprints,
		&t.Error, &t.CreatedBy, &t.StartedAt, &finished)
	if err != nil {
		return t, err
	}
	t.Targets = ParseTargets(targets)
	if finished.Valid {
		t.FinishedAt = finished.Time
	}
	return t, nil
}

// ListDiscoverTasks 分页列出任务（status 为空表示全部）。
func (s *Store) ListDiscoverTasks(status string, limit, offset int) ([]model.DiscoverTask, error) {
	q := `SELECT ` + taskColumns + ` FROM discover_tasks`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	// 排序键带 id 兜底：同一秒内起多个任务时，只按时间排序会让分页出现
	// "某行在两页都出现/都不出现"。
	q += ` ORDER BY started_at DESC, id DESC`
	q, args = applyPage(q, args, limit, offset)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.DiscoverTask, 0, 16)
	for rows.Next() {
		t, err := scanDiscoverTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountDiscoverTasks 任务总数（配合分页用）。
func (s *Store) CountDiscoverTasks(status string) (int, error) {
	q := `SELECT COUNT(*) FROM discover_tasks`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}

// GetDiscoverTask 按 ID 取任务；不存在返回 (nil, nil)，让调用方自己决定 404。
func (s *Store) GetDiscoverTask(id string) (*model.DiscoverTask, error) {
	row := s.db.QueryRow(`SELECT `+taskColumns+` FROM discover_tasks WHERE id=?`, id)
	t, err := scanDiscoverTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// PruneDiscoverTasks 只保留最近 keep 条。
//
// 任务账本身很小（一条几百字节），但没有上限的表迟早变成"没人敢删的历史包袱"。
// 保留最近 500 条，覆盖得住"上个月那次全端口扫描"这种回溯需求。
func (s *Store) PruneDiscoverTasks(keep int) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	res, err := s.db.Exec(`DELETE FROM discover_tasks WHERE id NOT IN (
		SELECT id FROM discover_tasks ORDER BY started_at DESC, id DESC LIMIT ?)`, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReapInterruptedDiscoverTasks 把上次进程退出时仍标记为 running 的任务收尾。
//
// 不这么做的话，重启后任务页会一直挂着几个永远不会结束的"运行中"，
// 而它们对应的 goroutine 早就不在了。启动时调一次即可。
func (s *Store) ReapInterruptedDiscoverTasks(now time.Time) (int64, error) {
	res, err := s.db.Exec(`UPDATE discover_tasks SET status='error', error=?, finished_at=?
		WHERE status='running'`, "进程重启，任务中断", now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
