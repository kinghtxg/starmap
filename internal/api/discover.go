package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/discover"
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

// discoverTask 一轮主动发现的任务状态（内存态，重启即丢；端口结果已落库）。
type discoverTask struct {
	ID           string             `json:"id"`
	Targets      []string           `json:"targets"`
	Profile      string             `json:"profile"`
	ProfileLabel string             `json:"profile_label"`
	Status       string             `json:"status"` // running | done | error
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
)

// discoverPlan 返回某档位的端口计划（让用户点"开始"之前就知道要扫多少端口）。
func (s *Server) discoverPlan(c *gin.Context) {
	profile := c.Query("profile")
	if profile == "" {
		profile = s.d.Cfg.DiscoverProfile
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
	if !s.d.Cfg.DiscoverEnabled {
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
		profile = s.d.Cfg.DiscoverProfile
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

	s.discMu.Lock()
	s.discSeq++
	id := "discover-" + strconv.FormatInt(s.discSeq, 10)
	task := &discoverTask{
		ID: id, Targets: targets, Profile: profile, ProfileLabel: label,
		Status: "running", Total: len(hosts), Started: time.Now(),
	}
	s.pruneDiscoverTasksLocked()
	s.discTasks[id] = task
	s.discMu.Unlock()

	go s.runDiscover(id, hosts, opt)

	s.d.Reviewer.Audit(s.actor(c), "discover_start", strings.Join(targets, ","),
		"profile="+profile+" hosts="+strconv.Itoa(len(hosts)))
	c.JSON(http.StatusAccepted, gin.H{
		"task_id": id, "status": "running", "hosts": len(hosts), "profile_label": label,
	})
}

// runDiscover 后台执行。
func (s *Server) runDiscover(id string, hosts []string, opt probe.DiscoverOptions) {
	// 单轮任务最长 6 小时：多网段全端口本来就慢，但不能无限挂着占资源
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
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
	defer s.discMu.Unlock()
	task := s.discTasks[id]
	if task == nil {
		return
	}
	task.Finished = time.Now()
	if err != nil {
		task.Status = "error"
		task.Error = err.Error()
		return
	}
	task.Status = "done"
	if res != nil {
		task.Total, task.Done = res.Total, res.Total
		task.Alive, task.OpenPorts, task.Fingerprints = res.Alive, res.OpenPorts, res.Fingerprints
		task.Hosts, task.Truncated = summarizeHosts(res.Hosts, discoverMaxAlive)
	}
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
		delete(s.discTasks, list[i].id)
	}
}

// discoverStatus 查询任务进度/结果。
func (s *Server) discoverStatus(c *gin.Context) {
	id := c.Param("id")
	s.discMu.Lock()
	task := s.discTasks[id]
	s.discMu.Unlock()
	if task == nil {
		fail(c, http.StatusNotFound, "发现任务不存在")
		return
	}
	c.JSON(http.StatusOK, task)
}
