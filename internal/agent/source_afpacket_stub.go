//go:build !linux

package agent

import (
	"errors"
	"runtime"
)

// OpenAFPacket 非 Linux 平台没有 AF_PACKET。
//
// Windows 用 npcap 后端，macOS 用 exec 后端（内置 tcpdump）。
// 这里返回明确的错误而不是"编不出来"——编不出来的话，交叉编译
// `GOOS=windows` 会直接失败，整个探针 Windows 版就没了。
func OpenAFPacket(iface string) (Source, error) {
	return nil, errors.New("afpacket 仅支持 Linux（当前 " + runtime.GOOS + "）：Windows 请用 -source npcap，macOS/其他请用 -source \"exec:tcpdump -i " + iface + " -w -\"")
}
