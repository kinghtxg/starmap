//go:build pcap

// 实时抓包实现：多网卡 gopacket/pcap（需要 CGO + libpcap）。
// 构建：go build -tags pcap ./...
package ingest

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"starmap/internal/parser"
)

// StartCapture 在多块网卡上启动实时抓包，合并输出到一个 PacketSource。
func StartCapture(ifaces []string, bpf string) (PacketSource, error) {
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("未指定抓包网卡")
	}
	ch := make(chan *parser.PacketInfo, 1024)
	var wg sync.WaitGroup
	var started int
	for _, iface := range ifaces {
		handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
		if err != nil {
			continue // 跳过不可用网卡
		}
		if bpf != "" {
			if err := handle.SetBPFFilter(bpf); err != nil {
				handle.Close()
				continue
			}
		}
		started++
		wg.Add(1)
		go func(h *pcap.Handle) {
			defer wg.Done()
			defer h.Close()
			src := gopacket.NewPacketSource(h, h.LinkType())
			src.DecodeOptions.Lazy = true
			src.DecodeOptions.NoCopy = true
			for pkt := range src.Packets() {
				if info := parser.ParsePacket(pkt); info != nil {
					ch <- info
				}
			}
		}(handle)
	}
	if started == 0 {
		return nil, fmt.Errorf("所有网卡均无法打开")
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch, nil
}

// CaptureAvailable 报告当前构建是否支持实时抓包。
func CaptureAvailable() bool { return true }
