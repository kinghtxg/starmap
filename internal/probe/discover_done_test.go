package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestDiscoverCancelledReportsRealDone 被取消的扫描必须如实报「实际处理了几台」。
//
// 这不是一个无关紧要的计数：任务页显示「254/254 已完成」和「0/254」，
// 用户对「要不要重扫一遍」的判断完全不同。早前 API 层把 Total 直接赋给 Done，
// 于是一个刚被停掉、一台都没扫的任务看起来像完美跑完了。
//
// 用「启动前就取消」构造确定性场景：所有主机 goroutine 一进 select 就命中
// ctx.Done()，done 恒为 0，不依赖任何网络时序。
func TestDiscoverCancelledReportsRealDone(t *testing.T) {
	withPortPlan(t, func(string) ([]int, string, error) {
		return []int{80}, "测试端口集", nil
	})
	s := newFPScanner(t)

	hosts := make([]string, 8)
	for i := range hosts {
		// 用文档保留段，绝不真的发出去
		hosts[i] = "192.0.2." + string(rune('1'+i))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 开跑之前就停

	res, err := s.Discover(ctx, hosts, DefaultDiscoverOptions())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 context.Canceled，实际 %v", err)
	}
	if res == nil {
		// 返回 nil 也行，但那样调用方就拿不到"计划扫多少"，无法展示部分进度。
		t.Fatal("取消时不应丢掉结果骨架（Total 是给界面兜底的）")
	}
	if res.Total != len(hosts) {
		t.Errorf("Total 应是计划主机数 %d，实际 %d", len(hosts), res.Total)
	}
	if res.Done != 0 {
		t.Errorf("一台都没扫时 Done 必须是 0，实际 %d —— 报成满额会让人误以为扫完了", res.Done)
	}
	if res.Done >= res.Total {
		t.Errorf("Done(%d) 不该达到 Total(%d)", res.Done, res.Total)
	}
}

// TestDiscoverDoneEqualsTotalOnSuccess 正常跑完时 Done 必须等于 Total。
//
// 与上一条配对：只断言"取消时 Done 小"不够——若实现退化成
// 「Done 永远是 0」，取消那条会绿，而正常任务会永远显示 0/1。
func TestDiscoverDoneEqualsTotalOnSuccess(t *testing.T) {
	withPortPlan(t, func(string) ([]int, string, error) {
		return []int{1}, "测试端口集", nil // 端口 1 必然关闭，只验证计数
	})
	s := newFPScanner(t)
	opt := DefaultDiscoverOptions()
	opt.Scan.Timeout = 200 * time.Millisecond
	opt.SkipFingerprint = true

	res, err := s.Discover(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, opt)
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if res.Total != 2 || res.Done != 2 {
		t.Errorf("正常结束应 Total=Done=2，实际 %d/%d", res.Done, res.Total)
	}
}
