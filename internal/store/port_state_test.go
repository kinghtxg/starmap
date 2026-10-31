package store

// 端口状态演进测试（V1.5.2 新增）。
//
// 背景：ports 表原先只有写入、没有状态演进，唯一的删除路径是资产被清理时连带删。
// 结果是"三年前开过 3389"和"今天开着 3389"在界面上完全一样，
// 端口列表会随时间永久腐烂，反过来误导处置优先级。

import (
	"testing"
	"time"

	"starmap/internal/model"
)

func mkPort(port int, lastSeen time.Time) *model.PortRecord {
	return &model.PortRecord{
		NodeKey:   "mac:aa:aa:aa:aa:aa:01",
		IP:        "10.0.0.1",
		Port:      port,
		Proto:     "tcp",
		Service:   "https-alt",
		State:     "open",
		Source:    "traffic",
		FirstSeen: lastSeen,
		LastSeen:  lastSeen,
	}
}

func TestMarkStalePorts(t *testing.T) {
	st := openTemp(t)
	now := time.Now()
	old := now.Add(-60 * 24 * time.Hour)

	if err := st.UpsertPort(mkPort(8443, old)); err != nil {
		t.Fatalf("写入旧端口失败: %v", err)
	}
	if err := st.UpsertPort(mkPort(443, now)); err != nil {
		t.Fatalf("写入新端口失败: %v", err)
	}

	n, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("标记 stale 失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只把 1 条过期端口标 stale，实际 %d", n)
	}

	ports, err := st.ListPorts("", "mac:aa:aa:aa:aa:aa:01")
	if err != nil {
		t.Fatalf("ListPorts: %v", err)
	}
	states := map[int]string{}
	for _, p := range ports {
		states[p.Port] = p.State
	}
	if states[8443] != "stale" {
		t.Fatalf("60 天未观测的端口应标为 stale，实际 %q", states[8443])
	}
	if states[443] != "open" {
		t.Fatalf("刚刚观测到的端口应保持 open，实际 %q", states[443])
	}
}

// TestStalePortReopensWhenSeenAgain 端口重新被观测到必须回到 open，
// 否则一次 stale 就成了永久误判。
func TestStalePortReopensWhenSeenAgain(t *testing.T) {
	st := openTemp(t)
	now := time.Now()
	old := now.Add(-60 * 24 * time.Hour)

	if err := st.UpsertPort(mkPort(3389, old)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if _, err := st.MarkStalePorts(now.Add(-PortStaleAfter)); err != nil {
		t.Fatalf("标记 stale 失败: %v", err)
	}

	// 重新观测到：state 与 last_seen 都应刷新
	if err := st.UpsertPort(mkPort(3389, now)); err != nil {
		t.Fatalf("重新写入失败: %v", err)
	}

	ports, err := st.ListPorts("", "mac:aa:aa:aa:aa:aa:01")
	if err != nil || len(ports) != 1 {
		t.Fatalf("ListPorts: %v len=%d", err, len(ports))
	}
	if ports[0].State != "open" {
		t.Fatalf("重新观测后应回到 open，实际 %q", ports[0].State)
	}
	if ports[0].LastSeen.Before(now.Add(-time.Minute)) {
		t.Fatalf("last_seen 未刷新: %v", ports[0].LastSeen)
	}
	// 首次发现时间不能被覆盖
	if ports[0].FirstSeen.After(old.Add(time.Minute)) {
		t.Fatalf("first_seen 被覆盖: %v", ports[0].FirstSeen)
	}
}

// TestMarkStalePortsIdempotent 重复执行不产生副作用（维护任务会周期性跑）。
func TestMarkStalePortsIdempotent(t *testing.T) {
	st := openTemp(t)
	now := time.Now()
	old := now.Add(-60 * 24 * time.Hour)
	if err := st.UpsertPort(mkPort(22, old)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	if _, err := st.MarkStalePorts(now.Add(-PortStaleAfter)); err != nil {
		t.Fatalf("第一次标记失败: %v", err)
	}
	n, err := st.MarkStalePorts(now.Add(-PortStaleAfter))
	if err != nil {
		t.Fatalf("第二次标记失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("已经 stale 的行不应再次被计数，实际 %d", n)
	}
}
