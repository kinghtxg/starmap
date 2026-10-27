//go:build linux

package agent

import (
	"testing"

	"github.com/google/gopacket/layers"
)

// TestEnablePromiscBadFD 非法 fd 必须报错而不是静默成功——
// 静默成功会让"混杂模式没设上"这件事永远查不出来。
func TestEnablePromiscBadFD(t *testing.T) {
	if err := enablePromisc(-1, 1); err == nil {
		t.Fatal("非法 fd 应返回错误")
	}
}

// TestOpenAFPacketUnknownIface 网卡名写错要立刻报错并带上名字。
func TestOpenAFPacketUnknownIface(t *testing.T) {
	if _, err := OpenAFPacket("definitely-not-a-real-iface0"); err == nil {
		t.Fatal("不存在的网卡应报错")
	}
}

// TestOpenAFPacketLoopback 真正开一次原始套接字。
// 需要 root 或 CAP_NET_RAW；普通用户下跳过（不是失败——这是环境限制，不是代码问题）。
func TestOpenAFPacketLoopback(t *testing.T) {
	src, err := OpenAFPacket("lo")
	if err != nil {
		t.Skipf("无 CAP_NET_RAW，跳过实际抓包: %v", err)
	}
	defer src.Close()
	if src.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("链路类型 = %v, 期望 Ethernet（lo 也是以太网封装）", src.LinkType())
	}
	if src.Name() != "afpacket:lo" {
		t.Errorf("Name() = %q", src.Name())
	}
}

// TestAFPacketCloseTwice Close 要幂等：退出路径上可能被调多次。
func TestAFPacketCloseTwice(t *testing.T) {
	src, err := OpenAFPacket("lo")
	if err != nil {
		t.Skipf("无 CAP_NET_RAW，跳过: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("第一次 Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("第二次 Close: %v", err)
	}
}
