//go:build !windows

package agent

import "errors"

// Device Npcap 枚举到的网卡（非 Windows 平台没有 Npcap，保留类型以统一调用方）。
// 字段必须与 windows 版保持一致，否则 cmd/starmap-probe 在交叉编译时会因为
// "Device 没有 Addrs 字段"直接编不过。
type Device struct {
	Name        string
	Description string
	Addrs       []string
}

// NpcapAvailable 非 Windows 平台没有 Npcap。
func NpcapAvailable() error {
	return errors.New("npcap 仅支持 Windows")
}

// ListNpcapDevices 非 Windows 平台没有 Npcap。
func ListNpcapDevices() ([]Device, error) {
	return nil, errors.New("npcap 仅支持 Windows")
}

// OpenNpcap 非 Windows 平台没有 Npcap。请用 afpacket（Linux）或 exec（macOS 内置 tcpdump）。
func OpenNpcap(device string) (Source, error) {
	return nil, errors.New("npcap 仅支持 Windows：Linux 用 -source afpacket，macOS 用 -source \"exec:tcpdump -i en0 -w -\"")
}
