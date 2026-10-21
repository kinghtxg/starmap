//go:build race

package topology

// raceEnabled 标记当前二进制是否启用了竞态检测。
// -race 会让执行速度下降 5~10 倍，任何耗时预算断言在它下面都不成立，
// 必须跳过而不是把阈值调到谁都拦不住。
const raceEnabled = true
