package api

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// 列表接口的服务端容量护栏。
//
// 为什么必须有：资产/端口/事件/审计都是"只增不减"的表。一次 /24 全端口扫描
// 就能产出上万个端口记录，检测引擎每 2 秒评估一轮会让事件持续累积。
// 没有上限时 `GET /api/ports` 会把整表读进内存、序列化成几十 MB JSON，
// 再交给浏览器一次性渲染——服务端 OOM、前端卡死，两边一起挂。
//
// 前端目前仍是"取回一页 + 本地分页"，所以这里给的是**硬护栏**而不是真分页：
// 超过上限的部分不返回，但用 X-Total-Count 告诉调用方"总数是多少、被截断了"。
// 真·服务端分页（前端传 page/size、后端只返回当前页）列为后续版本待办。
const (
	listDefaultLimit = 2000 // 不传 limit 时的默认条数
	listMaxLimit     = 5000 // 显式传 limit 时的硬上限
)

// pageParams 解析 limit/offset 并夹取到安全范围。
// 非法值（负数、非数字、超大）一律退回默认值，绝不把用户输入直接拼进 SQL。
func pageParams(c *gin.Context) (limit, offset int) {
	limit = listDefaultLimit
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > listMaxLimit {
		limit = listMaxLimit
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// setListMeta 回写列表元信息（总数 + 本次上限）。
// 前端据 total > len(list) 判断"被截断"，提示用户用筛选或翻页收窄，而不是默默少显示几条。
func setListMeta(c *gin.Context, total, limit int) {
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.Header("X-Result-Limit", strconv.Itoa(limit))
	// 跨域部署（cors_origins 非空）时，自定义响应头默认对 JS 不可见
	c.Header("Access-Control-Expose-Headers", "X-Total-Count,X-Result-Limit")
}

// maxKeywordLen 列表模糊搜索的关键字长度上限（按字符数，不是字节数）。
//
// 为什么要截断：LIKE '%...%' 无法走索引，SQLite 会对每一行跑一次模式匹配。
// 关键字越长，单行匹配越慢，几万行累起来就是肉眼可见的卡顿。
// 64 个字符足够定位任何一台设备，再长的关键字实际是误粘贴。
const maxKeywordLen = 64

// queryKeyword 取列表的模糊搜索关键字。
//
// 同时接受 q 与 keyword：前端各页历史命名不统一，与其改一堆前端不如两个都认。
func queryKeyword(c *gin.Context) string {
	kw := c.Query("q")
	if kw == "" {
		kw = c.Query("keyword")
	}
	kw = strings.TrimSpace(kw)
	if utf8.RuneCountInString(kw) > maxKeywordLen {
		// 按 rune 截断，不能按字节切——中文关键字按下标切会切出半个字符
		kw = string([]rune(kw)[:maxKeywordLen])
	}
	return kw
}
