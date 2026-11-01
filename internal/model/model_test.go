package model

// FiveTuple.Key() 的契约测试。
//
// 这个函数看起来简单到不值得测，但它有两个不能出错的性质：
//  1. **必须双向对称**：A→B 与 B→A 要落到同一个会话。交换一下顺序就聚合成两个，
//     会话数翻倍、字节数各算一半，检测规则全部失真。
//  2. **输出格式是持久化契约**：key 会作为会话标识写进 sessions 表，
//     跨版本读回老数据。格式一变，全部历史会话都会变成"新会话"。
//
// 第 2 条平时看不出来——改了格式，代码照样跑，只是运维第二天会问
// "为什么拓扑里的会话全是刚出现的"。所以这里钉死字面值。

import (
	"strconv"
	"testing"
)

// TestFiveTupleKeyLiteral 格式字面值回归。
//
// 这条断言**故意写死字符串**。如果哪天想改 Key 的拼接方式（换分隔符、
// 换成 socket 形式的 "ip:port<->ip:port"），这里会失败——那是提醒，
// 不是障碍：改格式必须同时给出会话迁移方案，否则老数据全成孤儿。
func TestFiveTupleKeyLiteral(t *testing.T) {
	cases := []struct {
		t    FiveTuple
		want string
	}{
		{
			FiveTuple{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Proto: "tcp"},
			"tcp|10.0.0.1:1234|10.0.0.2:80",
		},
		{
			FiveTuple{SrcIP: "192.168.1.10", DstIP: "172.16.0.1", SrcPort: 55000, DstPort: 443, Proto: "udp"},
			"udp|172.16.0.1:443|192.168.1.10:55000",
		},
	}
	for _, c := range cases {
		if got := c.t.Key(); got != c.want {
			t.Errorf("Key() = %q，期望 %q", got, c.want)
		}
	}
}

// TestFiveTupleKeySymmetric 双向必须落到同一个 key。
func TestFiveTupleKeySymmetric(t *testing.T) {
	forward := FiveTuple{SrcIP: "10.1.2.3", DstIP: "10.9.8.7", SrcPort: 40000, DstPort: 22, Proto: "tcp"}
	backward := FiveTuple{SrcIP: forward.DstIP, DstIP: forward.SrcIP, SrcPort: forward.DstPort, DstPort: forward.SrcPort, Proto: forward.Proto}
	if forward.Key() != backward.Key() {
		t.Fatalf("双向 key 不同：%q vs %q（会话会聚合成两个）", forward.Key(), backward.Key())
	}
}

// TestFiveTupleKeyNoCollision 不同的五元组不能撞 key。
//
// 撞了的后果是两条无关的会话被合并成一条，字节数和时长都变成两者之和——
// 在拓扑上看就是"某台机器和不相干的机器之间有一条流量"。
func TestFiveTupleKeyNoCollision(t *testing.T) {
	tuples := []FiveTuple{
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 443, Proto: "tcp"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 443, DstPort: 80, Proto: "tcp"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 443, Proto: "udp"}, // 仅协议不同
		{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 443, Proto: "tcp"}, // 对称 → 与第 1 条同 key，预期
		{SrcIP: "10.0.0.10", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 443, Proto: "tcp"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.20", SrcPort: 80, DstPort: 443, Proto: "tcp"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 0, DstPort: 443, Proto: "tcp"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 0, Proto: "tcp"},
	}
	seen := map[string]int{}
	for i, tp := range tuples {
		seen[tp.Key()]++
		_ = i
	}
	// 第 1 条与第 4 条是对称的，必然共用 key；其余每条都该独一份。
	if len(seen) != len(tuples)-1 {
		ks := make([]string, 0, len(seen))
		for k := range seen {
			ks = append(ks, k)
		}
		t.Fatalf("不同五元组产生了 %d 个 key，期望 %d（有碰撞）: %v", len(seen), len(tuples)-1, ks)
	}
}

// TestItoa 自定义 itoa 必须与 strconv 一致（端口拼接靠它）。
//
// 自己实现是因为 Key() 在报文热路径上，每次会话查表都调一次。
// 但"为了快自己写"最容易在边界上出错：0、进位、多位数的顺序。
func TestItoa(t *testing.T) {
	// 端口范围 0~65535，再补几个大值
	vals := []int{0, 1, 9, 10, 11, 99, 100, 999, 1000, 9999, 10000, 65535}
	for _, v := range vals {
		if got, want := itoa(v), strconv.Itoa(v); got != want {
			t.Errorf("itoa(%d) = %q，期望 %q", v, got, want)
		}
	}
}
