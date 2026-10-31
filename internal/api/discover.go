package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/discover"
	"starmap/internal/logging"
	"starmap/internal/model"
	"starmap/internal/probe"
)

// 主动发现 API（1.2）：内置 TCP 端口扫描 + 服务指纹。
//
// 与 /api/ports/scan（nmap 路径）的关系：
//   - /api/ports/scan 需要机器上装 nmap，适合"已经装了 nmap 且有授权"的环境；
//   - /api/discover/run 纯 Go 实现，无外部依赖、自带限速与时间窗口，
//     是内网装不上工具时仍然能跑起来的那条路。
//
// 两条路并存而不是替换：nmap 的 -sV 版本识别确实更强，能装就继续用；
// 装不上不该等于"没有主动发现能力"。
//
// 执行与落库逻辑在 internal/discover（与周期任务共用），本文件只管 HTTP 层。

// discoverTask 一轮主动发现的任务状态。
//
// 1.6 起是**双层**的：内存这份负责进度（每台主机都会更新，写库太贵），
// store 里的 discover_tasks 负责历史（只在开始与结束各写一次）。
// 进程重启后内存这份没了，任务页与详情仍可从库里读出来——这正是 1.5 及
// 之前最大的缺口：运维问「上周三扫的那轮跑完了吗」，答案只在日志里。
type discoverTask struct {
	ID           string             `json:"id"`
	Targets      []string           `json:"targets"`
	Profile      string             `json:"profile"`
	ProfileLabel string             `json:"profile_label"`
	Status       string             `json:"status"` // running | done | error | cancelled
	Total        int                `json:"total"`
	Done         int                `json:"done"`
	Alive        int                `json:"alive"`
	OpenPorts    int                `json:"open_ports"`
	Fingerprints int                `json:"fingerprints"`
	Current      string             `json:"current"`
	Error        string             `json:"error,omitempty"`
	Truncated    bool               `json:"truncated,omitempty"`
	Started      time.Time          `json:"started"`
	Finished     time.Time          `json:"finished,omitempty"`
	CreatedBy    string             `json:"created_by,omitempty"`
	Hosts        []discoverHostJSON `json:"hosts,omitempty"`
}

// discoverHostJSON 单主机结果。只回活跃主机：/24 一次就是 254 条，
// 把不活跃的也塞进响应只会让界面滚出一屏"无"。
type discoverHostJSON struct {
	IP       string   `json:"ip"`
	Ports    []int    `json:"ports"`
	Services []string `json:"services"` // 形如 "8080 泛微 e-cology"
	Title    string   `json:"title,omitempty"`
	TLSCN    string   `json:"tls_cn,omitempty"`
	TLSNames []string `json:"tls_names,omitempty"`
	Product  string   `json:"product,omitempty"`
	Elapsed  string   `json:"elapsed,omitempty"`
}

const (
	discoverMaxAlive = 200 // 任务详情里最多回多少台活跃主机
	discoverTaskKeep = 50  // 内存里最多保留多少个任务
	// discoverTaskHistoryKeep 任务账（discover_tasks）保留条数。
	// 一条任务几百字节，500 条不到 1MB；覆盖得住"上个月那次全网段扫描"的回溯需求。
	discoverTaskHistoryKeep = 500
)

// discoverPlan 返回某档位的端口计划（让用户点"开始"之前就知道要扫多少端口）。
func (s *Server) discoverPlan(c *gin.Context) {
	profile := c.Query("profile")
	if profile == "" {
		profile = s.cfg().DiscoverProfile
	}
	ports, label, err := probe.PortPlan(profile)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"profile":    profile,
		"label":      label,
		"port_count": len(ports),
	})
}

// discoverRun 触发一次主动发现（异步执行，立即返回 task_id）。
func (s *Server) discoverRun(c *gin.Context) {
	var body struct {
		Targets     []string `json:"targets"`
		Target      string   `json:"target"` // 兼容逗号 / 分号 / 换行分隔的单字段写法
		Profile     string   `json:"profile"`
		Fingerprint *bool    `json:"fingerprint"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if s.d.Discover == nil {
		fail(c, http.StatusServiceUnavailable, "主动发现执行器未初始化")
		return
	}
	if !s.cfg().DiscoverEnabled {
		// 主动扫描会在目标侧留下大量连接记录，必须由管理员显式开启后才允许。
		fail(c, http.StatusServiceUnavailable,
			"主动发现未启用：请先在系统配置中开启 discover_enabled（或在 config.yaml 中设置）")
		return
	}

	targets := make([]string, 0, len(body.Targets)+1)
	for _, t := range body.Targets {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if body.Target != "" {
		for _, t := range strings.FieldsFunc(body.Target, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\t'
		}) {
			if t = strings.TrimSpace(t); t != "" {
				targets = append(targets, t)
			}
		}
	}
	if len(targets) == 0 {
		fail(c, http.StatusBadRequest, "缺少 target（IP 或 CIDR，多个用逗号分隔）")
		return
	}

	profile := strings.TrimSpace(body.Profile)
	if profile == "" {
		profile = s.cfg().DiscoverProfile
	}
	_, label, err := probe.PortPlan(profile)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := probe.ExpandTargets(targets, discover.MaxHosts)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	opt := s.d.Discover.Options(profile, body.Fingerprint)

	id := s.newDiscoverTaskID()
	task := &discoverTask{
		ID: id, Targets: targets, Profile: profile, ProfileLabel: label,
		Status: "running", Total: len(hosts), Started: time.Now(),
		CreatedBy: s.actor(c),
	}
	// 用 Background 而不是 c.Request.Context()：任务的生命周期比这次 HTTP 请求长，
	// 请求一返回 ctx 就被取消，扫描会在第一台主机之后无声终止。
	// 停止要走 /api/tasks/:id/cancel，那边的 cancel 存在 s.discCancel 里。
	ctx, cancel := context.WithCancel(context.Background())

	s.discMu.Lock()
	s.pruneDiscoverTasksLocked()
	s.discTasks[id] = task
	s.discCancel[id] = cancel
	s.discMu.Unlock()

	s.saveTaskStart(task)

	go s.runDiscover(ctx, id, hosts, opt)

	s.d.Reviewer.Audit(s.actor(c), "discover_start", strings.Join(targets, ","),
		"profile="+profile+" hosts="+strconv.Itoa(len(hosts))+" task="+id)
	c.JSON(http.StatusAccepted, gin.H{
		"task_id": id, "status": "running", "hosts": len(hosts), "profile_label": label,
	})
}

// newDiscoverTaskID 生成任务 ID。
//
// 1.5 及之前是 "discover-" + 进程内自增序号，进程一重启就回到 discover-1，
// 与库里已有的同名任务撞主键——任务账落库之后这条老路必须堵掉。
// 现在用「毫秒时间 + 原子序号」：跨重启不重复，按 ID 排序近似按时间排序，
// 日志里一眼能看出是哪天扫的。
func (s *Server) newDiscoverTaskID() string {
	seq := atomic.AddInt64(&s.discSeq, 1)
	return "discover-" + strconv.FormatInt(time.Now().UnixMilli(), 36) +
		"-" + strconv.FormatInt(seq, 36)
}

// saveTaskStart 把任务开始写进任务账。失败只记日志：留不下历史是遗憾，
// 但让一次扫描因为"记账失败"而跑不起来是本末倒置。
func (s *Server) saveTaskStart(t *discoverTask) {
	if s.d.Store == nil {
		return
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	err := s.d.Store.StartDiscoverTask(model.DiscoverTask{
		ID: t.ID, Targets: t.Targets, Profile: t.Profile, ProfileLabel: t.ProfileLabel,
		Status: t.Status, Total: t.Total, StartedAt: t.Started, CreatedBy: t.CreatedBy,
	})
	if err != nil {
		logging.FromContext(context.Background()).Warn("发现任务记账失败",
			logging.Err(err), logging.Fmt("task", t.ID))
		return
	}
	// 任务账保留最近 500 条。放在这里顺带裁一次，比再起一个 ticker 省事：
	// 任务本来就不是高频动作，没人起任务的时候也就没有新行要裁。
	if _, err := s.d.Store.PruneDiscoverTasks(discoverTaskHistoryKeep); err != nil {
		logging.FromContext(context.Background()).Warn("发现任务裁剪失败", logging.Err(err))
	}
}

// saveTaskFinish 把任务收尾写回任务账（正常/报错/取消都走这里）。
func (s *Server) saveTaskFinish(t *discoverTask) {
	if s.d.Store == nil {
		return
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	err := s.d.Store.FinishDiscoverTask(model.DiscoverTask{
		ID: t.ID, Targets: t.Targets, Profile: t.Profile, ProfileLabel: t.ProfileLabel,
		Status: t.Status, Total: t.Total, Done: t.Done, Alive: t.Alive,
		OpenPorts: t.OpenPorts, Fingerprints: t.Fingerprints, Error: t.Error,
		StartedAt: t.Started, FinishedAt: t.Finished, CreatedBy: t.CreatedBy,
	})
	if err != nil {
		logging.FromContext(context.Background()).Warn("发现任务收尾记账失败",
			logging.Err(err), logging.Fmt("task", t.ID))
	}
}

// runDiscover 后台执行。
func (s *Server) runDiscover(ctx context.Context, id string, hosts []string, opt probe.DiscoverOptions) {
	// 单轮任务最长 6 小时：多网段全端口本来就慢，但不能无限挂着占资源
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()

	res, err := s.d.Discover.Run(ctx, hosts, opt, func(p probe.Progress) {
		s.discMu.Lock()
		if t := s.discTasks[id]; t != nil {
			t.Done, t.Alive, t.OpenPorts, t.Fingerprints = p.Done, p.Alive, p.OpenPorts, p.Fingerprints
			t.Current = p.IP
		}
		s.discMu.Unlock()
	})

	s.discMu.Lock()
	task := s.discTasks[id]
	if task == nil {
		s.discMu.Unlock()
		return
	}
	task.Finished = time.Now()
	task.Current = ""
	switch {
	case errors.Is(err, context.Canceled):
		// 人点了「停止」。和 error 分开记：一个是被我们打断，
		// 一个是跑挂了，运维看到之后要做的事完全不同。
		task.Status = model.DiscoverTaskStatusCancelled
		task.Error = "已手动停止"
	case errors.Is(err, context.DeadlineExceeded):
		// 必须排在通用 err 之前：6 小时上限触发时 err 就是 DeadlineExceeded，
		// 落到下面那条会把 "context deadline exceeded" 原样甩给用户。
		task.Status = "error"
		task.Error = "任务超过 6 小时上限，已中止"
	case err != nil:
		task.Status = "error"
		task.Error = err.Error()
	default:
		task.Status = "done"
	}
	if res != nil {
		// 只认 Total 是"计划扫多少"，Done 必须用实际处理数。
		// 之前这里写的是 `task.Total, task.Done = res.Total, res.Total`：
		// 正常跑完时两者相等看不出问题，一旦被取消或超时中断，
		// 界面上就会出现「254/254 已完成」而实际一台都没扫完——
		// 用户据此判断"已经扫过了，不用重扫"，结论直接错。
		task.Total, task.Done = res.Total, res.Done
		task.Alive, task.OpenPorts, task.Fingerprints = res.Alive, res.OpenPorts, res.Fingerprints
		task.Hosts, task.Truncated = summarizeHosts(res.Hosts, discoverMaxAlive)
	}
	// 拷一份快照再解锁：saveTaskFinish 要写库（可能几百毫秒），
	// 抱着 discMu 写库会让所有进度更新和状态查询一起卡住。
	snap := *task
	delete(s.discCancel, id)
	s.discMu.Unlock()

	s.saveTaskFinish(&snap)
}

// summarizeHosts 只保留活跃主机的精简视图（按 IP 数值序，不是字符串序）。
func summarizeHosts(hosts []probe.HostResult, max int) ([]discoverHostJSON, bool) {
	discover.SortHostsByIP(hosts)
	out := make([]discoverHostJSON, 0, 16)
	truncated := false
	for i := range hosts {
		h := &hosts[i]
		if !h.Alive {
			continue
		}
		if len(out) >= max {
			truncated = true
			break
		}
		item := discoverHostJSON{IP: h.IP, Elapsed: h.Elapsed, Ports: make([]int, 0, len(h.Ports))}
		for _, p := range h.Ports {
			item.Ports = append(item.Ports, p.Port)
		}
		for _, fp := range h.Fingerprints {
			if item.Title == "" && fp.Title != "" {
				item.Title = fp.Title
			}
			if item.TLSCN == "" && fp.TLSCN != "" {
				item.TLSCN = fp.TLSCN
			}
			if len(item.TLSNames) == 0 && len(fp.TLSNames) > 0 {
				item.TLSNames = fp.TLSNames
			}
			if item.Product == "" && fp.Product != "" {
				item.Product = fp.Product
			}
			if fp.Product != "" || fp.Title != "" {
				line := strconv.Itoa(fp.Port) + " "
				if fp.Product != "" {
					line += fp.Product
					if fp.Version != "" {
						line += " " + fp.Version
					}
				} else {
					line += fp.Title
				}
				item.Services = append(item.Services, line)
			}
		}
		sort.Ints(item.Ports)
		out = append(out, item)
	}
	return out, truncated
}

// pruneDiscoverTasksLocked 任务表按启动时间裁剪（调用方需持锁）。
func (s *Server) pruneDiscoverTasksLocked() {
	if len(s.discTasks) < discoverTaskKeep {
		return
	}
	type kv struct {
		id string
		at time.Time
	}
	list := make([]kv, 0, len(s.discTasks))
	for id, t := range s.discTasks {
		list = append(list, kv{id: id, at: t.Started})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	for i := 0; i < len(list)-discoverTaskKeep+1; i++ {
		// 连取消句柄一起删：只删 discTasks 会让 discCancel 单调增长，
		// 每个句柄都钉着一份 ctx，长跑实例上就是一条慢性内存泄漏。
		if c, ok := s.discCancel[list[i].id]; ok {
			c()
			delete(s.discCancel, list[i].id)
		}
		delete(s.discTasks, list[i].id)
	}
}

// discoverStatus 查询任务进度/结果。
//
// 先查内存（有实时进度），查不到再查任务账——进程重启后内存里没有，
// 但历史任务仍应能点开看结果统计，否则任务页点进去全是 404。
func (s *Server) discoverStatus(c *gin.Context) {
	id := c.Param("id")
	s.discMu.Lock()
	task := s.discTasks[id]
	if task != nil {
		// 必须持锁拷一份再序列化：后台 goroutine 正在写 Done/Alive/Current 等字段，
		// 把 *discoverTask 直接交给 c.JSON 就是边读边写（CI 的 -race 抓到的就是这个）。
		// 浅拷贝够用——Hosts 只在收尾时整体赋值一次，之后不再原地改元素。
		snap := *task
		s.discMu.Unlock()
		c.JSON(http.StatusOK, snap)
		return
	}
	s.discMu.Unlock()

	if s.d.Store == nil {
		fail(c, http.StatusNotFound, "发现任务不存在")
		return
	}
	t, err := s.d.Store.GetDiscoverTask(id)
	if err != nil {
		internalError(c, err, "读取任务失败")
		return
	}
	if t == nil {
		fail(c, http.StatusNotFound, "发现任务不存在")
		return
	}
	c.JSON(http.StatusOK, taskToJSON(t))
}
