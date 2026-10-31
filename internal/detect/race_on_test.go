//go:build race

package detect

// raceEnabled 标记当前二进制是否启用了竞态检测。
// -race 让执行速度下降 5~10 倍，任何耗时预算断言在它下面都不成立，
// 必须整条跳过——把阈值放到"谁都拦不住"等于没有这道闸门。
const raceEnabled = true
