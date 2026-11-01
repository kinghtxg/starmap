package simnet

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// TestDeterministic 同 seed 必须逐字节相同。
//
// 这条是所有断言的地基：如果同一场景两次跑出来的会话流不一样，"上次通过"
// 就不能说明任何事，CI 会变成随机数生成器。rand 的用法（先取端口再取时间、
// 循环里的取样顺序）任何一处改动都会打破它，所以必须有测试钉住。
func TestDeterministic(t *testing.T) {
	a := Clean(42, t0).Sessions()
	b := Clean(42, t0).Sessions()
	if len(a) != len(b) {
		t.Fatalf("会话数不一致：%d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].FiveTuple != b[i].FiveTuple || a[i].BytesUp != b[i].BytesUp ||
			a[i].BytesDown != b[i].BytesDown || !a[i].FirstSeen.Equal(b[i].FirstSeen) ||
			a[i].ProbeID != b[i].ProbeID || a[i].MAC != b[i].MAC {
			t.Fatalf("第 %d 条会话不一致：\n%+v\n%+v", i, a[i], b[i])
		}
	}
}

// TestSeedChangesWorld 不同 seed 应当产出不同世界，否则"随机丢包/时间铺开"
// 其实没生效，场景之间就没有差异覆盖。
func TestSeedChangesWorth(t *testing.T) {
	a := PartialObservation(1, t0).Sessions()
	b := PartialObservation(2, t0).Sessions()
	if len(a) == len(b) {
		// 长度可能偶然相同，比内容
		same := true
		for i := range a {
			if a[i].FiveTuple != b[i].FiveTuple || !a[i].FirstSeen.Equal(b[i].FirstSeen) {
				same = false
				break
			}
		}
		if same {
			t.Fatal("不同 seed 产出完全相同的世界，随机性没生效")
		}
	}
}

// TestMACOnlyVisibleSameSegment 只有与源同网段的探针才看得到源 MAC。
//
// 这是真实网络的二层事实：跨三层转发后源 MAC 已被网关替换。如果生成器
// 到处都给 MAC，测出来的"按 MAC 归一"就是假的——真实环境里根本拿不到。
//
// 判据必须按**探针**分，不能按"这个地址属于哪个网段"：同一条跨段会话
// 源在 A 段，A 段探针拿得到 MAC，B 段探针拿不到，两者是不同的事实。
func TestMACOnlyVisibleSameSegment(t *testing.T) {
	w := Clean(7, t0)
	segOf := map[string]string{}
	for i := range w.Hosts {
		segOf[w.Hosts[i].IPs[0]] = w.Hosts[i].Segment
	}
	probeSeg := map[string]string{"probe-a": "10.1.1.0/24", "probe-b": "10.1.2.0/24"}
	crossWithMAC, crossWithoutMAC, sameSegMissing := 0, 0, 0
	for _, s := range w.Sessions() {
		srcSeg := segOf[s.FiveTuple.SrcIP]
		if srcSeg == probeSeg[s.ProbeID] {
			if s.MAC == "" {
				sameSegMissing++
			}
			continue
		}
		if s.MAC != "" {
			crossWithMAC++
		} else {
			crossWithoutMAC++
		}
	}
	if sameSegMissing > 0 {
		t.Fatalf("%d 条与源同网段的会话没带 MAC——二层证据本来拿得到", sameSegMissing)
	}
	if crossWithMAC > 0 {
		t.Fatalf("%d 条跨段会话带了源 MAC——真实网络里跨三层看不到源 MAC，生成器给的证据是假的", crossWithMAC)
	}
	if crossWithoutMAC == 0 {
		t.Fatal("场景里没有跨段会话，这条断言空转")
	}
}

// TestNATRewritesSource NAT 场景：目的网段侧看到的源必须是出口地址，且拿不到 MAC。
func TestNATRewritesSource(t *testing.T) {
	w := NAT(7, t0)
	natOut := IPIn("10.3.2.0/24", 2)
	sawOuter, sawInner := 0, 0
	for _, s := range w.Sessions() {
		if s.ProbeID == "pin" {
			sawInner++
			if s.FiveTuple.SrcIP == natOut {
				t.Fatalf("内网探针不该看到 NAT 后的地址：%+v", s.FiveTuple)
			}
			if s.MAC == "" {
				t.Fatal("内网探针应当看得到内网源 MAC")
			}
			continue
		}
		sawOuter++
		if s.FiveTuple.SrcIP != natOut {
			t.Fatalf("机房探针看到的源应为 NAT 出口 %s，实际 %s", natOut, s.FiveTuple.SrcIP)
		}
		if s.MAC != "" {
			t.Fatalf("NAT 后源 MAC 已被替换，不该有：%+v", s.FiveTuple)
		}
	}
	if sawInner == 0 || sawOuter == 0 {
		t.Fatalf("NAT 两侧都要有观测，实际 内=%d 外=%d", sawInner, sawOuter)
	}
}

// TestLossDropsProportion 30% 漏采应当大致落在这个量级（防止"设了参数没生效"）。
func TestLossDropsProportion(t *testing.T) {
	w := PartialObservation(7, t0)
	full := 0
	for range w.Links {
		full++
	}
	got := len(w.Sessions()) // 该场景只有一个探针
	ratio := float64(got) / float64(full)
	if ratio < 0.6 || ratio > 0.85 {
		t.Fatalf("30%% 漏采后应剩 60~85%%，实际 %.0f%%（%d/%d）", ratio*100, got, full)
	}
}

// TestSessionsStayWithinWorld 观测不能凭空造出真值里没有的设备/端口。
func TestSessionsStayWithinWorld(t *testing.T) {
	for _, w := range All(11, t0) {
		ipOwner := map[string]bool{}
		openPort := map[string]map[uint16]bool{}
		for i := range w.Hosts {
			h := &w.Hosts[i]
			for _, ip := range h.IPs {
				ipOwner[ip] = true
			}
			openPort[h.Name] = map[uint16]bool{}
			for _, s := range h.Listen {
				openPort[h.Name][s.Port] = true
			}
		}
		for _, s := range w.Sessions() {
			if !ipOwner[s.FiveTuple.SrcIP] {
				t.Fatalf("[%s] 观测里出现真值没有的源地址 %s", w.Name, s.FiveTuple.SrcIP)
			}
			if !ipOwner[s.FiveTuple.DstIP] {
				t.Fatalf("[%s] 观测里出现真值没有的目的地址 %s", w.Name, s.FiveTuple.DstIP)
			}
		}
	}
}

// TestScenariosHaveDistinctNames 场景名要唯一，否则 CI 日志里分不清是谁红的。
func TestScenariosHaveDistinctNames(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range All(3, t0) {
		if w.Name == "" {
			t.Fatal("场景没有名字")
		}
		if seen[w.Name] {
			t.Fatalf("场景名重复：%s", w.Name)
		}
		seen[w.Name] = true
	}
	if len(seen) < 6 {
		t.Fatalf("场景太少（%d），覆盖不到多观察者/时钟/漏采/冲突这些坑", len(seen))
	}
}

// TestIPInAndMACOfFormat 基础生成函数不能产出非法值。
func TestIPInAndMACOfFormat(t *testing.T) {
	for n := 1; n <= 254; n++ {
		ip := IPIn("10.9.8.0/24", n)
		if ip != fmt.Sprintf("10.9.8.%d", n) {
			t.Fatalf("IPIn(10.9.8.0/24, %d) = %s", n, ip)
		}
	}
	if a, b := MACOf(1), MACOf(2); a == b {
		t.Fatal("MACOf 产生重复")
	}
	if MACOf(1) != "02:00:00:00:00:01" {
		t.Fatalf("MAC 格式不对：%s", MACOf(1))
	}
}
