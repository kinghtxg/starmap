package api

// CSV 导出（V1.6）。
//
// 为什么要有：StarMap 的定位是"理清网内结构"，而结构梳理完的下一步
// 永远是**交给别人**——交给等保整改的人、交给资产系统做对账、交给领导看。
// 没有导出，用户只能截图或者自己写脚本调 API，这两种做法都会让产品
// 停在"自己看看"的层级。
//
// 两个必须做对的地方：
//  1. **CSV 注入**。资产名/备注/页面标题都是外部可控内容（页面标题直接来自
//     被扫描主机返回的 <title>），以 = + - @ 开头会被 Excel 当公式执行。
//     这不是理论风险：扫到一台返回 `=cmd|'/c calc'!A0` 标题的设备就够了。
//  2. **UTF-8 BOM**。没有 BOM 的 CSV 在中文 Windows 的 Excel 里是乱码，
//     而"用 Excel 打开"是这类文件唯一的使用方式。

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/model"
	"starmap/internal/store"
)

const (
	// exportPageSize 分页拉取的批大小。导出走"翻页流式写"，不一次性把
	// 整表读进内存：一次 /16 全端口扫描就是几十万条端口记录，
	// 全量读进内存再序列化会让导出一个动作把服务端内存顶上去。
	exportPageSize = 2000
	// exportMaxRows 单次导出的硬上限。超过就不再往下写，并在最后一行前
	// 留一句提示——静默截断比拒绝导出更糟：用户会以为拿到的是全量。
	exportMaxRows = 200000
	// exportConcurrency 同时允许的导出数。取 2：一次导出已经能把单核打满，
	// 留一个名额给"两个人同时点导出"这种正常场景，再多就是自己压自己。
	exportConcurrency = 2
)

// exportGuard 限制导出并发。
//
// 名额满时回 429 而不是排队：排队会让浏览器一直转圈，用户以为服务挂了，
// 再点几次反而把并发推得更高。429 配合前端的 toast，一眼能看懂。
func (s *Server) exportGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 结构体直接构造的测试可能没有初始化名额，退化成"不限制"，
		// 而不是因为 nil channel 永远拿不到名额、把所有导出都挡成 429。
		if s.exportSem == nil {
			c.Next()
			return
		}
		select {
		case s.exportSem <- struct{}{}:
			defer func() { <-s.exportSem }()
			c.Next()
		default:
			fail(c, http.StatusTooManyRequests, "同时进行的导出过多，请稍后再试")
			c.Abort()
		}
	}
}

// csvSafe 防 CSV 公式注入。
//
// 前缀一个单引号是 Excel/LibreOffice 都认的"当文本看"约定。
// 只处理真正危险的起始字符，不动数字（前导单引号会让 22 变成文本，
// 下游脚本一算就错）。
func csvSafe(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		// 纯数字/纯负号开头的数值不算注入（-1 是很常见的端口差值）。
		if isNumericLike(s) {
			return s
		}
		return "'" + s
	}
	return s
}

// isNumericLike 判断是否是可安全保留的数值字面量。
func isNumericLike(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// csvWriter 导出器：统一负责表头、BOM、注入防护与截断提示。
type csvWriter struct {
	c    *gin.Context
	w    *csv.Writer
	rows int
	// truncated 达到上限后置位，收尾时补一行说明。
	truncated bool
}

// newCSV 开始一个 CSV 响应。
//
// 文件名只用 ASCII：Content-Disposition 里的中文需要 RFC 5987 的
// filename*=UTF-8”... 编码，而各家浏览器/下载器对它的处理并不一致，
// 坏的结果是文件名变成一串 %E4%B8...。英文名 + 日期足够区分。
func newCSV(c *gin.Context, kind string, header []string) (*csvWriter, error) {
	name := fmt.Sprintf("starmap-%s-%s.csv", kind, time.Now().Format("20060102-1504"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	// 导出会读全表，明确告诉中间的反代/浏览器别缓存这份快照
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	// UTF-8 BOM：中文 Windows 的 Excel 没有它会按 GBK 解码，整列乱码
	if _, err := c.Writer.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return nil, err
	}
	w := csv.NewWriter(c.Writer)
	if err := w.Write(header); err != nil {
		return nil, err
	}
	return &csvWriter{c: c, w: w}, nil
}

// add 写一行。返回 false 表示已达上限，调用方应停止翻页。
func (e *csvWriter) add(row ...string) bool {
	if e.rows >= exportMaxRows {
		e.truncated = true
		return false
	}
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	// csv.Writer 的写错误（客户端断开）无法在这里上报给用户，
	// 但不处理会让后面每一行都白跑；记下来直接停。
	if err := e.w.Write(row); err != nil {
		e.truncated = true
		return false
	}
	e.rows++
	return true
}

// done 收尾：补截断说明并 flush。
func (e *csvWriter) done() {
	if e.truncated {
		_ = e.w.Write([]string{
			fmt.Sprintf("（已达单次导出上限 %d 行，其余请用筛选条件分批导出）", exportMaxRows),
		})
	}
	e.w.Flush()
}

// exportAssets 导出资产台账。
func (s *Server) exportAssets(c *gin.Context) {
	f := store.AssetFilter{Status: c.Query("status"), Keyword: queryKeyword(c)}
	ew, err := newCSV(c, "assets", []string{
		"IP", "MAC", "主机名", "操作系统", "状态", "归属人", "归属单位",
		"物理位置", "备注", "首次发现", "最后发现", "节点标识",
	})
	if err != nil {
		return
	}
	defer ew.done()

	for offset := 0; ; offset += exportPageSize {
		list, err := s.d.Store.ListAssetsPaged(f, exportPageSize, offset)
		if err != nil {
			// 已经吐出去的字节收不回来，只能中断；此时客户端会拿到一个
			// 不完整但语法正确的 CSV（列数一致），比半截 JSON 好处理。
			return
		}
		for i := range list {
			a := &list[i]
			ok := ew.add(
				strings.Join(a.IPs, " "), a.MAC, a.Hostname, a.OS,
				assetStatusLabel(a.Status), a.Owner, a.Department, a.Location,
				a.Description, fmtTime(a.FirstSeen), fmtTime(a.LastSeen), a.NodeKey,
			)
			if !ok {
				return
			}
		}
		if len(list) < exportPageSize {
			return
		}
	}
}

// assetStatusLabel 状态中文化（导出给人看，不是给程序解析）。
func assetStatusLabel(s string) string {
	switch s {
	case model.AssetArchived:
		return "已归档"
	case model.AssetUnarchived:
		return "未归档"
	}
	return s
}

// exportPorts 导出端口记录。
func (s *Server) exportPorts(c *gin.Context) {
	f := store.PortFilter{IP: c.Query("ip"), NodeKey: c.Query("node_key"), Keyword: queryKeyword(c)}
	ew, err := newCSV(c, "ports", []string{
		"IP", "端口", "协议", "服务", "状态", "来源", "产品", "版本",
		"页面标题", "TLS CN", "favicon", "首次发现", "最后发现", "节点标识",
	})
	if err != nil {
		return
	}
	defer ew.done()

	for offset := 0; ; offset += exportPageSize {
		list, err := s.d.Store.ListPortsPaged(f, exportPageSize, offset)
		if err != nil {
			return
		}
		for i := range list {
			p := &list[i]
			ok := ew.add(
				p.IP, strconv.Itoa(p.Port), p.Proto, p.Service, p.State, p.Source,
				p.Product, p.Version, p.Title, p.TLSCN, p.Favicon,
				fmtTime(p.FirstSeen), fmtTime(p.LastSeen), p.NodeKey,
			)
			if !ok {
				return
			}
		}
		if len(list) < exportPageSize {
			return
		}
	}
}

// exportEvents 导出风险事件。
func (s *Server) exportEvents(c *gin.Context) {
	f := store.EventFilter{
		Status:  c.Query("status"),
		Type:    c.Query("type"),
		Keyword: queryKeyword(c),
	}
	ew, err := newCSV(c, "events", []string{
		"时间", "类型", "级别", "状态", "标题", "详情", "节点标识",
	})
	if err != nil {
		return
	}
	defer ew.done()

	for offset := 0; ; offset += exportPageSize {
		list, err := s.d.Store.ListEventsPaged(f, exportPageSize, offset)
		if err != nil {
			return
		}
		for i := range list {
			ev := &list[i]
			ok := ew.add(
				fmtTime(ev.CreatedAt), ev.Type, ev.Level, ev.Status,
				ev.Title, ev.Detail, ev.NodeKey,
			)
			if !ok {
				return
			}
		}
		if len(list) < exportPageSize {
			return
		}
	}
}

// exportTasks 导出主动发现任务账。
func (s *Server) exportTasks(c *gin.Context) {
	status := strings.TrimSpace(c.Query("status"))
	if !validTaskStatus(status) {
		fail(c, http.StatusBadRequest, "status 取值只能是 running / done / error / cancelled")
		return
	}
	ew, err := newCSV(c, "tasks", []string{
		"任务 ID", "目标", "档位", "状态", "主机总数", "已完成", "存活主机",
		"开放端口", "识别指纹", "发起人", "开始时间", "结束时间", "错误",
	})
	if err != nil {
		return
	}
	defer ew.done()

	for offset := 0; ; offset += exportPageSize {
		list, err := s.d.Store.ListDiscoverTasks(status, exportPageSize, offset)
		if err != nil {
			return
		}
		for i := range list {
			t := &list[i]
			ok := ew.add(
				t.ID, strings.Join(t.Targets, " "), t.ProfileLabel, t.Status,
				strconv.Itoa(t.Total), strconv.Itoa(t.Done), strconv.Itoa(t.Alive),
				strconv.Itoa(t.OpenPorts), strconv.Itoa(t.Fingerprints),
				t.CreatedBy, fmtTime(t.StartedAt), fmtTime(t.FinishedAt), t.Error,
			)
			if !ok {
				return
			}
		}
		if len(list) < exportPageSize {
			return
		}
	}
}

// fmtTime 统一时间格式（本地时间，秒精度）。
//
// 不用 RFC3339：Excel 认不出 `2026-03-04T15:04:05+08:00` 里的 T 和偏移，
// 会当文本处理，用户没法按时间排序。空格分隔是两边都认的形态。
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}
