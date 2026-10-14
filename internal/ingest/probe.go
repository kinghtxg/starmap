// 远端探针 HTTP 上报接收（POST /api/ingest/probe）。
package ingest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"starmap/internal/parser"
)

// ProbeReport 探针上报的数据模型：一批解析前的原始报文元信息。
type ProbeReport struct {
	ProbeID  string              `json:"probe_id" binding:"required"`
	SentAt   time.Time           `json:"sent_at"`
	Packets  []parser.PacketInfo `json:"packets" binding:"required"`
	Metadata map[string]string   `json:"metadata,omitempty"`
}

// ProbeHandler 返回 gin.HandlerFunc，将探针上报的报文写入 PacketSource 通道。
// out: 内部报文通道（由调用方聚合到 parser.Aggregator）。
func ProbeHandler(out chan<- *parser.PacketInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		var report ProbeReport
		if err := c.ShouldBindJSON(&report); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "上报格式错误: " + err.Error()})
			return
		}
		accepted := 0
		for i := range report.Packets {
			p := &report.Packets[i]
			if p.Timestamp.IsZero() {
				p.Timestamp = report.SentAt
			}
			select {
			case out <- p:
				accepted++
			default: // 通道满则丢弃，避免阻塞 HTTP 请求
			}
		}
		c.JSON(http.StatusOK, gin.H{"accepted": accepted, "total": len(report.Packets)})
	}
}
