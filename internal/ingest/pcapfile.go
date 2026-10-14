// Package ingest 数据接入层：PCAP/PCAPNG 文件导入、网卡实时抓包、远端探针上报。
// 输出统一为 PacketSource channel（SPEC §2 数据流起点）。
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"starmap/internal/parser"
)

// PacketSource 报文通道：抓包/文件/探针的统一输出形态。
// 数据流：PacketSource → parser.Aggregator → topology.Engine。
type PacketSource <-chan *parser.PacketInfo

// ErrNotEnabled 实时抓包未启用（默认构建无 libpcap）。
var ErrNotEnabled = errors.New("未启用实时抓包：请使用 -tags pcap 构建并安装 libpcap")

// OpenPCAPFile 解析 PCAP 或 PCAPNG 文件，返回 PacketSource。
// 在 goroutine 中读取，读取完毕或出错后关闭 channel。
func OpenPCAPFile(path string) (PacketSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 PCAP 文件失败: %w", err)
	}
	// 通过魔数识别格式：0xa1b2c3d4 / 0xd4c3b2a1 = PCAP，0x0a0d0d0a = PCAPNG
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("读取文件头失败: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	ch := make(chan *parser.PacketInfo, 256)

	isPCAPNG := magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}
	isPCAP := magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4} ||
		magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1} ||
		magic == [4]byte{0xa1, 0xb2, 0x3c, 0x4d} || // 纳秒精度
		magic == [4]byte{0x4d, 0x3c, 0xb2, 0xa1}
	if !isPCAP && !isPCAPNG {
		f.Close()
		return nil, fmt.Errorf("无法识别的文件格式（魔数 %x）", magic)
	}

	go func() {
		defer close(ch)
		defer f.Close()
		var src *gopacket.PacketSource
		if isPCAPNG {
			r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
			if err != nil {
				return
			}
			src = gopacket.NewPacketSource(r, layers.LinkTypeEthernet)
		} else {
			r, err := pcapgo.NewReader(f)
			if err != nil {
				return
			}
			src = gopacket.NewPacketSource(r, r.LinkType())
		}
		src.DecodeOptions.Lazy = true
		src.DecodeOptions.NoCopy = true
		for pkt := range src.Packets() {
			if info := parser.ParsePacket(pkt); info != nil {
				ch <- info
			}
		}
	}()
	return ch, nil
}

// OpenPCAPReader 从 io.Reader 解析 PCAP（用于 multipart 上传）。
func OpenPCAPReader(r io.Reader) (PacketSource, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "starmap-upload-*.pcap")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	tmp.Close()
	src, err := OpenPCAPFile(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	// 转发并在读完后清理临时文件，避免 /tmp 泄漏
	out := make(chan *parser.PacketInfo, 256)
	go func() {
		defer close(out)
		defer os.Remove(tmp.Name())
		for p := range src {
			out <- p
		}
	}()
	return out, nil
}
