//go:build windows

package agent

import (
	"bytes"
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

// Windows 上通过 syscall 直接调 wpcap.dll（Npcap 提供）。
//
// 为什么不用 gopacket/pcap：那条路径需要 CGO，也就是需要一个 C 编译器。
// 目标机器（开发机、办公终端）通常没有 gcc，装 MinGW 又要几百兆和管理员权限。
// 而 Npcap 本身多半已经装了（Wireshark / 各种客户端带装）。用 syscall 直连
// 就能做到"有 Npcap 就能跑，不需要编译器、不需要 Wireshark"。
//
// 只用到 5 个函数：open_live / next_ex / datalink / close / findalldevs。
// 刻意不用回调式 API（pcap_loop + 回调），因为把 Go 函数指针交给 C 需要
// cgo 的导出机制；pcap_next_ex 是轮询式的，纯 syscall 就能驾驭。
var (
	wpcapDLL = syscall.NewLazyDLL("wpcap.dll")

	procOpenLive = wpcapDLL.NewProc("pcap_open_live")
	procNextEx   = wpcapDLL.NewProc("pcap_next_ex")
	procDatalink = wpcapDLL.NewProc("pcap_datalink")
	procClose    = wpcapDLL.NewProc("pcap_close")
	procGetErr   = wpcapDLL.NewProc("pcap_geterr")
	procFindAll  = wpcapDLL.NewProc("pcap_findalldevs")
	procFreeAll  = wpcapDLL.NewProc("pcap_freealldevs")
)

// pcapPkthdr 对应 C 的 struct pcap_pkthdr。
// Windows 的 struct timeval 是 {long tv_sec; long tv_usec;}，两个 32 位；
// 加 caplen / len 两个 u32，共 16 字节，无额外填充。
type pcapPkthdr struct {
	TsSec  int32
	TsUsec int32
	Caplen uint32
	Len    uint32
}

// pcapIf 对应 C 的 struct pcap_if（x64：8*4 + 4 + 4 填充 = 40 字节）。
type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   unsafe.Pointer
	Flags       uint32
}

// pcapAddr 对应 C 的 struct pcap_addr。
type pcapAddr struct {
	Next      *pcapAddr
	Addr      *syscall.RawSockaddrAny
	Netmask   *syscall.RawSockaddrAny
	Broadaddr *syscall.RawSockaddrAny
	Dstaddr   *syscall.RawSockaddrAny
}

// Device Npcap 枚举到的网卡。
type Device struct {
	Name        string
	Description string
	// Addrs 该网卡上的 IP。没有 IP 基本就是没接网线 / 虚拟网卡，
	// 选网卡时这是比描述文字可靠得多的判据。
	Addrs []string
}

// devAddrs 从 pcap_addr 链表里取 IP。只看地址族，不关心端口。
func devAddrs(head unsafe.Pointer) []string {
	var out []string
	for a := (*pcapAddr)(head); a != nil && a.Addr != nil; a = a.Next {
		switch a.Addr.Addr.Family {
		case syscall.AF_INET:
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(a.Addr))
			out = append(out, net.IP(sa.Addr[:]).String())
		case syscall.AF_INET6:
			sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(a.Addr))
			out = append(out, net.IP(sa.Addr[:]).String())
		}
	}
	return out
}

// NpcapAvailable 报告 wpcap.dll 是否可用（Npcap 是否安装）。
func NpcapAvailable() error {
	return wpcapDLL.Load()
}

// ListNpcapDevices 枚举可抓包的网卡。
func ListNpcapDevices() ([]Device, error) {
	if err := NpcapAvailable(); err != nil {
		return nil, fmt.Errorf("未找到 wpcap.dll：请先安装 Npcap（勾选 WinPcap API 兼容模式）: %w", err)
	}
	// errbuf 必须在堆上且比 PCAP_ERRBUF_SIZE(256) 大：pcap 会往里写最多 256 字节，
	// 而我们要把它当 C 字符串扫到 NUL 为止。用 [256]byte 恰好贴边，
	// 一旦消息写满 256 字节没有结束符，扫描就会越过数组边界。
	errbuf := make([]byte, 512)
	var alldevs *pcapIf
	rc, _, _ := procFindAll.Call(
		uintptr(unsafe.Pointer(&alldevs)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if int32(rc) != 0 {
		return nil, fmt.Errorf("枚举网卡失败: %s", cString(&errbuf[0], len(errbuf)))
	}
	if alldevs != nil {
		defer procFreeAll.Call(uintptr(unsafe.Pointer(alldevs)))
	}
	var out []Device
	for p := alldevs; p != nil; p = p.Next {
		out = append(out, Device{
			Name:        cString(p.Name, 512),
			Description: cString(p.Description, 512),
			Addrs:       devAddrs(p.Addresses),
		})
	}
	return out, nil
}

type npcapSource struct {
	name   string
	ch     chan Frame
	stop   chan struct{}
	handle uintptr
	lt     layers.LinkType
	once   sync.Once
	closed int32
}

func (s *npcapSource) Name() string              { return s.name }
func (s *npcapSource) Frames() <-chan Frame      { return s.ch }
func (s *npcapSource) LinkType() layers.LinkType { return s.lt }

// Close 只发停止信号，句柄由采集协程自己关。
//
// 不能在这里直接 pcap_close：采集协程可能正卡在 pcap_next_ex 内部，
// 而这函数用的句柄正被我们在外面释放——典型的 use-after-free，
// 表现是退出时进程偶尔直接崩掉、没有任何 Go 栈。让持有者自己收尾才安全。
func (s *npcapSource) Close() error {
	s.once.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		close(s.stop)
	})
	return nil
}

// OpenNpcap 在指定网卡上抓包。device 传 ListNpcapDevices 返回的 Name
// （形如 `\Device\NPF_{GUID}`）；传空则取第一块有描述的网卡。
func OpenNpcap(device string) (Source, error) {
	if err := NpcapAvailable(); err != nil {
		return nil, fmt.Errorf("未找到 wpcap.dll：请先安装 Npcap: %w", err)
	}
	if device == "" {
		devs, err := ListNpcapDevices()
		if err != nil {
			return nil, err
		}
		if len(devs) == 0 {
			return nil, fmt.Errorf("没有可抓包的网卡")
		}
		device = devs[0].Name
	}

	devPtr, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, fmt.Errorf("网卡名非法: %w", err)
	}
	errbuf := make([]byte, 512)
	// snaplen 65535 / promisc 1 / to_ms 200：200ms 超时让轮询能被 ctx 及时打断。
	h, _, _ := procOpenLive.Call(
		uintptr(unsafe.Pointer(devPtr)),
		uintptr(65535),
		uintptr(1),
		uintptr(200),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if h == 0 {
		msg := cString(&errbuf[0], len(errbuf))
		if msg == "" {
			msg = "未知原因"
		}
		return nil, fmt.Errorf("打开网卡失败: %s（常见原因：未以管理员身份运行，或该网卡被 Npcap 限制访问）", msg)
	}

	// pcap_datalink 返回 int（DLT_*）。必须按 int32 收窄再转 LinkType（uint8），
	// 直接拿 uintptr 硬转会把高位的符号扩展当成链路类型，得到一个荒唐的值。
	lt := layers.LinkTypeEthernet
	if dl, _, _ := procDatalink.Call(h); int32(dl) != 1 { // 1 = DLT_EN10MB
		lt = layers.LinkType(uint8(int32(dl)))
	}

	s := &npcapSource{
		name:   "npcap:" + device,
		ch:     make(chan Frame, 512),
		stop:   make(chan struct{}),
		handle: h,
		lt:     lt,
	}
	go s.loop()
	return s, nil
}

func (s *npcapSource) loop() {
	defer func() {
		// 句柄由本协程关闭：退出路径上 pcap_next_ex 一定已经返回了。
		if s.handle != 0 {
			procClose.Call(s.handle)
		}
		close(s.ch)
	}()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		var hdr *pcapPkthdr
		var data *byte
		rc, _, _ := procNextEx.Call(
			s.handle,
			uintptr(unsafe.Pointer(&hdr)),
			uintptr(unsafe.Pointer(&data)),
		)
		switch int32(rc) {
		case 1:
			if hdr == nil || data == nil || hdr.Caplen == 0 {
				continue
			}
			n := int(hdr.Caplen)
			// 立刻复制：Npcap 的这段内存在下一次 next_ex 后即失效。
			buf := make([]byte, n)
			copy(buf, unsafe.Slice(data, n))
			ts := time.Unix(int64(hdr.TsSec), int64(hdr.TsUsec)*1000)
			select {
			case s.ch <- Frame{Data: buf, TS: ts}:
			case <-s.stop:
				return
			}
		case 0:
			continue // 超时，正常
		case -2:
			return // 读到文件尾（离线句柄才会出现）
		default:
			// -1 是错误。把 pcap_geterr 打出来：网卡被拔、驱动被替换、
			// 权限被收回都走这条路，没有这条日志就只剩一句"源结束了"。
			if atomic.LoadInt32(&s.closed) == 0 {
				if msg := s.lastErr(); msg != "" {
					slog.Default().Error("Npcap 抓包中断", "device", s.name, "err", msg)
				}
			}
			return
		}
	}
}

// lastErr 取最近一次 pcap 错误描述。
func (s *npcapSource) lastErr() string {
	rc, _, _ := procGetErr.Call(s.handle)
	if rc == 0 {
		return ""
	}
	// pcap_geterr 返回的是 char*，但 syscall 只能把它当 uintptr 交出来。
	// 这里用类型双关落成指针，而不是直接 unsafe.Pointer(rc)：
	// 后者会被 go vet 的 unsafeptr 判为误用（确实，单独把一个来路不明的
	// uintptr 转成指针是危险的；这里的来路是明确的 DLL 返回值）。
	var p unsafe.Pointer
	*(*uintptr)(unsafe.Pointer(&p)) = rc
	return cString((*byte)(p), 1024)
}

// cString 读 C 字符串，最多扫 max 字节。
// max 由调用方按"这块内存至少有多大"给：对 errbuf 这种自己分配的缓冲区，
// 必须传真实长度，否则 NUL 缺失时会读出边界。
func cString(p *byte, max int) string {
	if p == nil || max <= 0 {
		return ""
	}
	b := unsafe.Slice(p, max)
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
