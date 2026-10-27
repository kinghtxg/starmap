//go:build linux

package agent

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket/layers"
)

// afPacketSource Linux AF_PACKET 原始套接字采集。
//
// 用纯 Go 的 syscall 直接开 SOCK_RAW，不经过 libpcap、不需要 CGO。
// 这是探针能"一条 go build 就出一个静态二进制"的关键——NAS、树莓派、
// 只装了 busybox 的跳板机上都能直接跑。
type afPacketSource struct {
	name   string
	ch     chan Frame
	stop   chan struct{}
	fd     int
	warn   error // 非致命问题（如混杂模式设置失败），启动时打出来
	once   sync.Once
	closed int32
}

func (s *afPacketSource) Name() string              { return s.name }
func (s *afPacketSource) Frames() <-chan Frame      { return s.ch }
func (s *afPacketSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

// Close 只发停止信号，fd 由采集协程自己关。
// 在外面 close 一个正在 recvfrom 的 fd 是危险的：内核把这个 fd 号回收后
// 可能立刻被别的协程的 socket 复用，正在进行的 recvfrom 就会读到别人的数据。
func (s *afPacketSource) Close() error {
	s.once.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		close(s.stop)
	})
	return nil
}

// 混杂模式相关常量（Linux 固定值，不随架构变化）。
const (
	solPacket           = 263
	packetAddMembership = 1
	packetMRPromisc     = 1
)

// packetMreq 对应 C 的 struct packet_mreq。
type packetMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]byte
}

// enablePromisc 把套接字切到混杂模式（内核会给网卡加一个 promisc 计数）。
//
// 这一步对探针是刚需而不是优化：接在镜像口 / 分光器上时，被镜像的流量
// 目标 MAC 都不是本机，网卡在非混杂模式下会在硬件层直接丢掉它们。
// 少了这一步，探针"起来了、也有日志、就是没有数据"——这种故障最难查，
// 因为每一步看起来都是对的。失败不致命（本机流量照样能抓），返回错误由调用方告警。
func enablePromisc(fd int, ifindex int) error {
	mreq := packetMreq{Ifindex: int32(ifindex), Type: packetMRPromisc}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solPacket),
		uintptr(packetAddMembership),
		uintptr(unsafe.Pointer(&mreq)),
		uintptr(unsafe.Sizeof(mreq)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("设置混杂模式失败（需要 CAP_NET_ADMIN）: %w", errno)
	}
	return nil
}

// OpenAFPacket 在指定网卡上抓包。需要 CAP_NET_RAW（root 或
// `setcap cap_net_raw,cap_net_admin=eip ./starmap-probe`）。
func OpenAFPacket(iface string) (Source, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("网卡 %q 不存在: %w", iface, err)
	}
	proto := int(htons(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败（需要 root 或 CAP_NET_RAW）: %w", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("设置非阻塞失败: %w", err)
	}
	// 4MB 接收缓冲：采样循环是"取空再睡 2ms"，缓冲太小会在突发流量下丢包。
	// 设不上不致命（内核会夹到 rmem_max），所以忽略错误。
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	sa := &syscall.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("绑定网卡 %q 失败: %w", iface, err)
	}

	s := &afPacketSource{
		name: "afpacket:" + iface,
		ch:   make(chan Frame, 512),
		stop: make(chan struct{}),
		fd:   fd,
	}
	if err := enablePromisc(fd, ifi.Index); err != nil {
		// 不中断：单机排查场景下非混杂也够用。但要明确说出来，
		// 否则接了镜像口抓不到东西时没有任何线索。
		s.warn = err
	}
	go s.loop()
	return s, nil
}

func (s *afPacketSource) loop() {
	defer func() {
		_ = syscall.Close(s.fd)
		close(s.ch)
	}()
	if s.warn != nil {
		slog.Default().Warn("混杂模式未启用，镜像口流量可能抓不到", "iface", s.name, "err", s.warn)
	}
	buf := make([]byte, 65536)
	// 复用一个定时器：空闲时每秒要醒 500 次，用 time.After 就是 500 个
	// 一次性 Timer 对象，纯属给 GC 添活。
	idle := time.NewTimer(2 * time.Millisecond)
	defer idle.Stop()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		// 内层循环把内核缓冲一次取空再睡。外层只取一个包的话，
		// 每条 EAGAIN 都要等 2ms，吞吐会被钉在 500 pps 左右——
		// 局域网上随便一个备份任务就能超过它，表现为"抓包一直在丢"。
		drained := 0
		for {
			if drained&255 == 0 {
				select {
				case <-s.stop:
					return
				default:
				}
			}
			n, _, err := syscall.Recvfrom(s.fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
					break // 取空了
				}
				if atomic.LoadInt32(&s.closed) == 0 {
					// 接口 down / 网卡被移除：明确报出来，不要假装还在抓。
					slog.Default().Error("AF_PACKET 抓包中断", "iface", s.name, "err", err)
				}
				return
			}
			if n <= 0 {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case s.ch <- Frame{Data: data, TS: time.Now()}:
			case <-s.stop:
				return
			}
			drained++
		}
		if drained > 0 {
			continue // 刚取到过包，直接回头再取，不睡
		}
		idle.Reset(2 * time.Millisecond)
		select {
		case <-s.stop:
			return
		case <-idle.C:
		}
	}
}

// htons 主机序转网络序。仅在 little-endian 上需要交换；
// Linux/amd64 与 arm64 都是 LE，大端平台（s390x 等）不在此项目支持范围内。
func htons(v uint16) uint16 { return v<<8 | v>>8 }
