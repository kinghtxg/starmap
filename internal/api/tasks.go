package api

// 主动发现任务账（V1.6）。
//
// 为什么要单开一页：1.5 及之前，一个扫描任务的完整生命只活在内存里
// （`discTasks` 那 50 条），进程重启即归零。现场的真实用法是——运维周一下午
// 起了一轮 10.0.0.0/16 全端口，周三回来问「跑完没、扫出多少」，而这时
// 那 50 条早就被后面的任务挤掉了，答案只剩日志里的几行 Info。
//
// 灯塔那类产品把"任务"做成第一入口，靠的就是这份历史账。这里补齐同一件事：
// 任务列表（可按状态筛）、详情（含结果统计）、取消（真打断 goroutine）。

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/logging"
	"starmap/internal/model"
)

// taskToJSON 把库里那条任务账转成与内存态一致的 DTO。
//
// 字段名保持一致是刻意的：前端任务列表点开详情时，可能先命中内存（有实时进度）
// 也可能命中历史（只有统计），两种来源不该让表格换一套列名。
func taskToJSON(t *model.DiscoverTask) discoverTask {
	return discoverTask{
		ID:           t.ID,
		Targets:      t.Targets,
		Profile:      t.Profile,
		ProfileLabel: t.ProfileLabel,
		Status:       t.Status,
		Total:        t.Total,
		Done:         t.Done,
		Alive:        t.Alive,
		OpenPorts:    t.OpenPorts,
		Fingerprints: t.Fingerprints,
		Error:        t.Error,
		Started:      t.StartedAt,
		Finished:     t.FinishedAt,
		CreatedBy:    t.CreatedBy,
	}
}

// validTaskStatus 允许筛选的状态白名单。
//
// 不接受任意字符串：status 直接进 SQL 的 WHERE 参数（虽然已参数化，
// 但一个拼错的状态名会让用户看到空列表并以为"任务都没了"）。
func validTaskStatus(s string) bool {
	switch s {
	case "", "running", "done", "error", model.DiscoverTaskStatusCancelled:
		return true
	}
	return false
}

// listTasks 任务列表（按开始时间倒序，可按状态筛）。
//
// 与 /api/discover/status/:id 的分工：那个是"盯一个正在跑的任务"，
// 这个是"回头看历史"。前者读内存，后者读库。
func (s *Server) listTasks(c *gin.Context) {
	if s.d.Store == nil {
		fail(c, http.StatusServiceUnavailable, "存储未初始化")
		return
	}
	status := strings.TrimSpace(c.Query("status"))
	if !validTaskStatus(status) {
		fail(c, http.StatusBadRequest, "status 取值只能是 running / done / error / cancelled")
		return
	}
	limit, offset := pageParams(c)

	total, err := s.d.Store.CountDiscoverTasks(status)
	if err != nil {
		internalError(c, err, "读取任务总数失败")
		return
	}
	list, err := s.d.Store.ListDiscoverTasks(status, limit, offset)
	if err != nil {
		internalError(c, err, "读取任务列表失败")
		return
	}
	out := make([]discoverTask, 0, len(list))
	for i := range list {
		// 正在跑的任务内存里有实时进度，覆盖掉库里那份（库里只在开始时写过一次）。
		if t := s.liveTask(list[i].ID); t != nil {
			out = append(out, *t)
			continue
		}
		out = append(out, taskToJSON(&list[i]))
	}
	setListMeta(c, total, limit)
	c.JSON(http.StatusOK, out)
}

// liveTask 取内存里的实时任务快照（无则 nil）。
func (s *Server) liveTask(id string) *discoverTask {
	s.discMu.Lock()
	defer s.discMu.Unlock()
	t := s.discTasks[id]
	if t == nil {
		return nil
	}
	snap := *t
	return &snap
}

// getTask 任务详情（含结果统计）。
func (s *Server) getTask(c *gin.Context) {
	id := c.Param("id")
	if t := s.liveTask(id); t != nil {
		c.JSON(http.StatusOK, t)
		return
	}
	if s.d.Store == nil {
		fail(c, http.StatusNotFound, "任务不存在")
		return
	}
	t, err := s.d.Store.GetDiscoverTask(id)
	if err != nil {
		internalError(c, err, "读取任务失败")
		return
	}
	if t == nil {
		fail(c, http.StatusNotFound, "任务不存在")
		return
	}
	c.JSON(http.StatusOK, taskToJSON(t))
}

// cancelTask 手动停止一轮正在进行的发现。
//
// 三种结果分开表达：
//   - 404 任务从来没存在过
//   - 409 任务存在但已经结束了（再点一次「停止」不该报错，但也不该假装成功）
//   - 202 已请求停止，扫描 goroutine 会在当前主机扫完后退出
//
// 取消是"请求"而不是"立即生效"：一次 TCP 连接探测可能已经在路上，
// 强行杀掉会留下一堆半开连接。等当前这台主机收尾再退是更干净的做法。
func (s *Server) cancelTask(c *gin.Context) {
	id := c.Param("id")

	s.discMu.Lock()
	_, running := s.discTasks[id]
	cancel := s.discCancel[id]
	s.discMu.Unlock()

	if running && cancel != nil {
		cancel()
		s.d.Reviewer.Audit(s.actor(c), "discover_cancel", id, "manual")
		c.JSON(http.StatusAccepted, gin.H{"task_id": id, "status": "cancelling"})
		return
	}
	if running {
		// 在内存里但拿不到 cancel：只可能是刚收尾、正在写库那一瞬间。
		fail(c, http.StatusConflict, "任务正在收尾，无法停止")
		return
	}

	// 内存里没有 → 要么早结束了，要么是重启前的历史任务。
	if s.d.Store == nil {
		fail(c, http.StatusNotFound, "任务不存在")
		return
	}
	t, err := s.d.Store.GetDiscoverTask(id)
	if err != nil {
		internalError(c, err, "读取任务失败")
		return
	}
	if t == nil {
		fail(c, http.StatusNotFound, "任务不存在")
		return
	}
	fail(c, http.StatusConflict, "任务已结束（当前状态: "+t.Status+"），无需停止")
}

// reapInterruptedTasks 把上次进程退出时仍标 running 的任务收尾（启动时调一次）。
//
// 不做的后果很具体：重启后任务页会永久挂着几个「运行中」，
// 而它们的 goroutine 早就不存在了；用户点「停止」还会拿到 409，看着像 bug。
func (s *Server) reapInterruptedTasks() {
	if s.d.Store == nil {
		return
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	n, err := s.d.Store.ReapInterruptedDiscoverTasks(time.Now())
	if err != nil {
		logging.FromContext(context.Background()).Warn("中断任务收尾失败", logging.Err(err))
		return
	}
	if n > 0 {
		logging.FromContext(context.Background()).Info("已收尾上次进程遗留的运行中任务",
			logging.Fmt("count", strconv.FormatInt(n, 10)))
	}
}
