package detect

import (
	"strings"
	"testing"
	"time"

	"starmap/internal/model"
)

// IP 冲突：同一地址上两台 MAC 不同的设备。
//
// 这两条用例一起说明一个边界：**判定靠 MAC，不靠 IP**。
// 同一个 MAC 反复出现（同一台机器的多条会话、重启后重报）绝不能报冲突，
// 否则一台机器自己就能刷出事件，这条规则会被值班的人直接忽略掉。

func TestIPConflictDetected(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	peer := "10.8.0.9"
	target := "10.8.0.30"
	macA, macB := "02:00:00:00:00:aa", "02:00:00:00:00:bb"

	// peer → target：target 作为目的端，此时只知道 IP，不知道 MAC（跨三层就是如此）
	s0 := bigSession(peer, target, "02:00:00:00:00:09", 40001, base)
	// target 上的第一台机器发包
	s1 := bigSession(target, peer, macA, 40002, base.Add(time.Second))
	// target 上的第二台机器发包（地址被抢 / ARP 欺骗）
	s2 := bigSession(target, peer, macB, 40003, base.Add(2*time.Second))
	setSessions(d, eng, s0, s1, s2)

	rc := newRuleContext(d, currentSessions(), base.Add(time.Minute))
	events := evalIPConflict(rc)
	if len(events) != 1 {
		t.Fatalf("应产出 1 条 IP 冲突事件，实际 %d：%+v", len(events), events)
	}
	e := events[0]
	if e.Type != model.EventTypeIPConflict {
		t.Fatalf("事件类型不对：%s", e.Type)
	}
	if e.Level != model.RiskMid {
		t.Fatalf("冲突事件级别应为 mid（地址冲突多为事故，ARP 欺骗才定性），实际 %s", e.Level)
	}
	if e.Evidence["ip"] != target || e.Evidence["count"] != "2" {
		t.Fatalf("证据不全：%+v", e.Evidence)
	}
	if !strings.Contains(e.Evidence["macs"], macA) || !strings.Contains(e.Evidence["macs"], macB) {
		t.Fatalf("证据里应有两个 MAC：%s", e.Evidence["macs"])
	}

	// 引擎侧：两台机器必须各成一个节点，且都打冲突标记
	nodes := eng.AllNodes()
	var owners []model.Node
	for _, n := range nodes {
		for _, ip := range n.IPs {
			if ip == target {
				owners = append(owners, n)
			}
		}
	}
	if len(owners) != 2 {
		t.Fatalf("冲突 IP 上应有 2 个节点，实际 %d：%+v", len(owners), owners)
	}
	for _, n := range owners {
		if !hasNodeLabel(&n, "ip-conflict") {
			t.Fatalf("节点 %s 没打 ip-conflict 标记，图上不会刺眼", n.NodeKey)
		}
	}
}

func TestSameMACIsNotConflict(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	peer, target := "10.8.1.9", "10.8.1.30"
	mac := "02:00:00:00:00:aa"

	s0 := bigSession(target, peer, mac, 40001, base)
	s1 := bigSession(target, peer, mac, 40002, base.Add(time.Second))
	s2 := bigSession(peer, target, "", 40003, base.Add(2*time.Second))
	s3 := bigSession(target, peer, mac, 40004, base.Add(3*time.Second))
	setSessions(d, eng, s0, s1, s2, s3)

	rc := newRuleContext(d, currentSessions(), base.Add(time.Minute))
	if events := evalIPConflict(rc); len(events) != 0 {
		t.Fatalf("同一 MAC 不该报冲突，实际 %d 条：%+v", len(events), events)
	}
	if got := len(eng.AllNodes()); got != 2 {
		t.Fatalf("同 MAC 应合并为同一节点，节点数应为 2（peer + target），实际 %d", got)
	}
}

// 无 MAC 参与时不能报冲突：那是"证据不足"，不是"两台设备"。
// 跨三层观测、只看到目的端时，一轮流量里根本没有 MAC —— 报成冲突就是纯误报。
func TestNoMACNoConflict(t *testing.T) {
	d, eng, _ := newTestDetector(t, fullCfg())
	a, b := "10.8.2.9", "10.8.2.30"
	s0 := bigSession(a, b, "02:00:00:00:00:11", 40001, base)
	s1 := bigSession(b, a, "", 40002, base.Add(time.Second))
	s2 := bigSession(a, b, "02:00:00:00:00:11", 40003, base.Add(2*time.Second))
	setSessions(d, eng, s0, s1, s2)

	rc := newRuleContext(d, currentSessions(), base.Add(time.Minute))
	if events := evalIPConflict(rc); len(events) != 0 {
		t.Fatalf("没有第二个 MAC 时不该报冲突：%+v", events)
	}
}
