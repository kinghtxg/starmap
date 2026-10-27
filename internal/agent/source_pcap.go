package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// pcap 魔数（同 internal/ingest/pcapfile.go）。
var (
	magicPCAP      = []byte{0xa1, 0xb2, 0xc3, 0xd4}
	magicPCAPRev   = []byte{0xd4, 0xc3, 0xb2, 0xa1}
	magicPCAPNS    = []byte{0xa1, 0xb2, 0x3c, 0x4d} // 纳秒精度
	magicPCAPNSRev = []byte{0x4d, 0x3c, 0xb2, 0xa1}
	magicNG        = []byte{0x0a, 0x0d, 0x0d, 0x0a}
)

// streamSource 从任意 pcap/pcapng 字节流读帧。
// file 与 exec 两个后端共用它，保证两条路径的解码行为完全一致。
type streamSource struct {
	name string
	ch   chan Frame
	lt   layers.LinkType

	stop   chan struct{}
	once   sync.Once
	closer func() error
}

func (s *streamSource) Name() string              { return s.name }
func (s *streamSource) Frames() <-chan Frame      { return s.ch }
func (s *streamSource) LinkType() layers.LinkType { return s.lt }

func (s *streamSource) Close() error {
	s.once.Do(func() {
		close(s.stop)
		if s.closer != nil {
			_ = s.closer()
		}
	})
	return nil
}

// openStream 嗅探魔数、构造解码器，然后起一个读协程。
// 解码器与链路类型在返回前就确定，这样调用方拿到的 Source 立刻可用。
//
// hdrTimeout 为等待头部数据的上限。对文件可以给 0（本地读不会挂），
// 对 exec 必须给：采集命令可能因为没权限、网卡名拼错、工具版本不认识参数
// 而"启动了但什么都不输出"。这种情况下 Peek 会永久阻塞，探针就那么僵在那里，
// 既没有错误也没有日志。
func openStream(name string, r io.Reader, closer func() error, hdrTimeout time.Duration) (Source, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head, err := peekHeader(br, 4, hdrTimeout)
	if err != nil {
		if closer != nil {
			_ = closer()
		}
		return nil, fmt.Errorf("读取采集流头部失败（命令没输出 pcap？）: %w", err)
	}

	var (
		rd   gopacket.PacketDataSource
		lt   layers.LinkType
		kind string
	)
	switch {
	case bytes.Equal(head, magicNG):
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			if closer != nil {
				_ = closer()
			}
			return nil, fmt.Errorf("解析 pcapng 头失败: %w", err)
		}
		rd, lt, kind = ng, ng.LinkType(), "pcapng"
	case bytes.Equal(head, magicPCAP), bytes.Equal(head, magicPCAPRev),
		bytes.Equal(head, magicPCAPNS), bytes.Equal(head, magicPCAPNSRev):
		p, err := pcapgo.NewReader(br)
		if err != nil {
			if closer != nil {
				_ = closer()
			}
			return nil, fmt.Errorf("解析 pcap 头失败: %w", err)
		}
		rd, lt, kind = p, p.LinkType(), "pcap"
	default:
		if closer != nil {
			_ = closer()
		}
		return nil, fmt.Errorf("无法识别的流格式（魔数 %x）：需要 pcap 或 pcapng", head)
	}

	s := &streamSource{
		name:   name + " (" + kind + ")",
		ch:     make(chan Frame, 512),
		lt:     lt,
		stop:   make(chan struct{}),
		closer: closer,
	}
	go s.loop(rd)
	return s, nil
}

func (s *streamSource) loop(rd gopacket.PacketDataSource) {
	defer close(s.ch)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		// 文件读完、采集进程被杀、管道断开，都会以 err 结束。
		// 这三者对探针是同一个语义——"源没了"，统一交给上层处理，不在这里区分。
		data, ci, err := rd.ReadPacketData()
		if err != nil {
			return
		}
		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		select {
		case s.ch <- Frame{Data: data, TS: ts}:
		case <-s.stop:
			return
		}
	}
}

// peekHeader 在 timeout 内取到 n 字节前瞻；timeout<=0 表示一直等。
func peekHeader(br *bufio.Reader, n int, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		return br.Peek(n)
	}
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := br.Peek(n)
		ch <- result{b, err}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-t.C:
		return nil, fmt.Errorf("等了 %s 没收到任何数据", timeout)
	}
}

// OpenFile 回放本地 pcap/pcapng 文件；path 为 "-" 时读 stdin。
// 用于三个场景：离线分析、回归测试、以及在无法实时抓包的机器上先跑通链路。
func OpenFile(path string) (Source, error) {
	if path == "-" {
		return openStream("stdin", os.Stdin, nil, 0)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	return openStream("file:"+path, f, f.Close, 0)
}
