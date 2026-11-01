package store

import (
	"testing"
	"time"
)

// perfBudget 返回耗时断言实际使用的上界。
//
// 覆盖插桩（-cover）会给每条语句插两次计数器写入，实测重型循环慢 30%~60%：
// 5 万行端口状态刷新裸跑 1.5s、插桩 2.1s。这些断言若按裸跑数字写死，
// CI 的覆盖率 job 会在那里稳定误报 —— 而覆盖率 job 恰恰是"完整跑法"
// （不带 -short）的唯一执行者，等于把回归守卫放在了它必炸的地方。
//
// 放宽的幅度是有限的：插桩最多让耗时翻一倍，这里给 2 倍；
// 而这些断言防的都是数量级劣化（20ms → 2s、1.5s → 几十秒），2 倍余量不损失判别力。
func perfBudget(d time.Duration) time.Duration {
	if testing.CoverMode() != "" {
		return 2 * d
	}
	return d
}
