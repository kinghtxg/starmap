// 触发性评估（Kick）的契约测试（V1.5.2）。
//
// Kick 是上报路径唯一的对接面：它必须永远不阻塞，否则「异步化」只是把
// 请求线程从等检测改成等信号量，问题原样还在。
package detect

import (
	"context"
	"testing"
	"time"

	"starmap/internal/model"
)

// TestKickTriggersEvaluationWithoutWaitingForPeriod Kick 应让事件在周期到来前产出。
func TestKickTriggersEvaluationWithoutWaitingForPeriod(t *testing.T) {
	d, eng, st := newTestDetector(t, fullCfg())
	d.Interval = time.Hour // 周期形同不存在，只能靠 Kick
	d.minKickInterval = 0

	s := frpSession(true, true, false)
	eng.Ingest(s)
	sessionList = []model.Session{*s}
	d.SessionsFunc = currentSessions

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	time.Sleep(20 * time.Millisecond) // 让 Run 进入 select

	d.Kick()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs, err := st.ListEvents(model.EventStatusPending, "")
		if err == nil && len(evs) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Kick 未在 2 秒内触发评估：上报后事件迟迟不出现")
}

// TestKickNeverBlocks 没有任何消费者时，Kick 也必须立即返回。
func TestKickNeverBlocks(t *testing.T) {
	d, _, _ := newTestDetector(t, fullCfg())
	// 不启动 Run：缓冲 1 很快被填满，后续调用必须走 default 分支丢弃。
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			d.Kick()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Kick 阻塞了：它是上报路径上的调用，一阻塞就把请求线程卡住")
	}
}

// TestKickOnNilDetector 未装配检测器时（部分部署形态）不得 panic。
func TestKickOnNilDetector(t *testing.T) {
	var d *Detector
	d.Kick() // 不应 panic
}
