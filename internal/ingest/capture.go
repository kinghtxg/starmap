//go:build !pcap

// 实时抓包 stub：默认构建（无 CGO/libpcap）返回"未启用实时抓包"。
// 真实实现见 capture_pcap.go，使用 -tags pcap 构建启用。
package ingest

// StartCapture 实时抓包入口（stub 版本）。
// ifaces: 网卡列表；bpf: BPF 过滤表达式。
func StartCapture(ifaces []string, bpf string) (PacketSource, error) {
	return nil, ErrNotEnabled
}

// CaptureAvailable 报告当前构建是否支持实时抓包。
func CaptureAvailable() bool { return false }
