package api

import (
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// 写接口的输入校验。
//
// 为什么每个字段都要限制长度：这些值会原样落库，再原样进列表、进拓扑标签、进审计详情、
// 进 CSV 导出，最后进别人的浏览器。一个 1MB 的"归属单位"不会立刻崩，
// 但会让每一次列表查询、每一次审计翻页都变慢，而且没有任何界面能把它显示完整。
// 全局 body 上限是兜底，字段级上限才是"这条数据本身是否合理"。
//
// 长度按**字符数**而非字节数计：中文名字用字节算会被误判（一个汉字 3 字节）。
const (
	maxNameLen   = 128  // 名称类：域名、主机名、归属人、操作系统
	maxNoteLen   = 2000 // 备注类：复核意见、白名单说明
	maxDescLen   = 512  // 描述类：资产备注、域名说明
	maxCIDRCount = 64   // 单个网络域最多包含多少个网段
	maxValueLen  = 256  // 白名单值（可能是 cidr / ip / mac / node key）
)

// colorRE 网络域颜色：#RRGGBB。
// 这个值会直接进 SVG/CSS，不校验就等于开了一个样式注入的口子。
var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// tooLong 判断是否超长（按字符数）。
func tooLong(s string, max int) bool {
	return utf8.RuneCountInString(s) > max
}

// checkField 校验单个字段并写回错误，返回 false 表示已拒绝。
func checkField(c *gin.Context, field, val string, max int) bool {
	if tooLong(val, max) {
		fail(c, http.StatusBadRequest,
			field+" 超长（上限 "+strconv.Itoa(max)+" 个字符）")
		return false
	}
	return true
}

// checkCIDRs 校验网段列表：数量上限 + 每项必须是合法 CIDR。
//
// 只校验格式不校验"是否内网"：产品的定位是内网测绘，但把公网网段写进域配置
// 并不会造成伤害（探测范围由探针/扫描配置单独控制），这里不做过度限制。
func checkCIDRs(c *gin.Context, cidrs []string) bool {
	if len(cidrs) > maxCIDRCount {
		fail(c, http.StatusBadRequest,
			"网段数量超限（最多 "+strconv.Itoa(maxCIDRCount)+" 个）")
		return false
	}
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err != nil {
			fail(c, http.StatusBadRequest, "非法网段："+s)
			return false
		}
	}
	return true
}

// checkColor 校验颜色格式；空值表示"用默认色"，放行。
func checkColor(c *gin.Context, color string) bool {
	color = strings.TrimSpace(color)
	if color == "" {
		return true
	}
	if !colorRE.MatchString(color) {
		fail(c, http.StatusBadRequest, "颜色格式应为 #RRGGBB，实际："+color)
		return false
	}
	return true
}
