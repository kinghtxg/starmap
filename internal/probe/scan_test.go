package probe

import (
	"errors"
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/topology"
)

func newTestScanner() (*Scanner, *topology.Engine) {
	eng := topology.New(model.SystemConfig{
		AgingSeconds: 3600, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
	})
	s := New(eng)
	s.NowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	return s, eng
}

func TestTriggerDisabled(t *testing.T) {
	s, _ := newTestScanner()
	if _, err := s.Trigger("icmp", "192.168.1.1"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("默认关闭应返回 ErrDisabled，实际 %v", err)
	}
}

func TestTriggerInvalidType(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	if _, err := s.Trigger("syn_scan", "192.168.1.1"); err == nil {
		t.Fatal("非法类型应报错")
	}
}

func TestTriggerICMPInject(t *testing.T) {
	s, eng := newTestScanner()
	s.SetEnabled(true)
	// 注入假 ping：存活
	s.lookPath = func(string) (string, error) { return "/bin/ping", nil }
	s.run = func(name string, args ...string) (string, error) {
		return "3 packets transmitted, 3 received\n64 bytes from 192.168.1.1: ttl=64", nil
	}
	res, err := s.Trigger("icmp", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("应有 1 存活主机: %+v", res)
	}
	// 结果注入拓扑
	if n := eng.NodeByIP("192.168.1.1"); n == nil || !n.Active {
		t.Fatal("探测结果应注入拓扑引擎")
	}
}

func TestTriggerICMPUnreachable(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	s.lookPath = func(string) (string, error) { return "/bin/ping", nil }
	s.run = func(name string, args ...string) (string, error) {
		return "", errors.New("exit 1")
	}
	res, err := s.Trigger("icmp", "192.168.1.99")
	if err == nil {
		t.Fatal("不可达应返回错误")
	}
	if res == nil || len(res.Hosts) != 0 {
		t.Fatal("不可达不应有主机")
	}
}

func TestTriggerNoPingGraceful(t *testing.T) {
	s, _ := newTestScanner()
	s.SetEnabled(true)
	// 环境无 ping/traceroute → 优雅降级报错，不 panic
	s.lookPath = func(string) (string, error) { return "", errors.New("not found") }
	if _, err := s.Trigger("icmp", "192.168.1.1"); err == nil {
		t.Fatal("无 ping 命令应报错")
	}
	if _, err := s.Trigger("traceroute", "8.8.8.8"); err == nil {
		t.Fatal("无 traceroute/ping 应报错")
	}
}

func TestParseTraceroute(t *testing.T) {
	out := "traceroute to 8.8.8.8\n 1  192.168.1.1  1 ms\n 2  * * *\n 3  100.64.0.1  5 ms\n"
	hits := parseTraceroute(out)
	if len(hits) != 2 || hits[0].IP != "192.168.1.1" || hits[1].Hop != 3 {
		t.Fatalf("解析错误: %+v", hits)
	}
}

func TestExpandTarget(t *testing.T) {
	ips, err := expandTarget("192.168.1.5", 254)
	if err != nil || len(ips) != 1 {
		t.Fatal(err)
	}
	ips, err = expandTarget("192.168.1.0/30", 254)
	if err != nil || len(ips) != 2 { // 去网络+广播
		t.Fatalf("/30 应展开 2 个主机地址，实际 %v", ips)
	}
	if _, err := expandTarget("10.0.0.0/8", 254); err == nil {
		t.Fatal("超大网段应拒绝")
	}
	if _, err := expandTarget("not-an-ip", 254); err == nil {
		t.Fatal("非法目标应报错")
	}
}
