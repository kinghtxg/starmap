package topology

import (
	"testing"
	"time"

	"starmap/internal/model"
)

// 网关身份归一（V1.10）。
//
// 网关是内网里最该被看见的设备，也是被动侧最难定死的一台：它的 IP 只在
// "别人连它"的会话里当目的地址，它的 MAC 只在"它转发公网流量"的会话里当
// 二层目的 MAC、在它自己发包时当源 MAC。这三条证据从不落在同一条会话上，
// 谁先到就由谁建节点——处理不好，同一台路由器在图上变成两台：一台有名有姓，
// 一台只有 MAC，而只有 MAC 那台才是真正在给全网转发的。
//
// 下面这个用例把"任意到达顺序都收敛成一台设备"钉死。判据不是"有没有节点"，
// 而是：**同一个 MAC 只有一个节点、两个 IP 都在它身上、10.8.1.1 没有第二个归属**。

const gwMAC = "02:00:00:00:00:c9"

func gwSessions(t0 time.Time) []*model.Session {
	dns := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.8.1.10", DstIP: "10.8.1.1", SrcPort: 40001, DstPort: 53, Proto: "tcp"},
		MAC:       "02:00:00:00:00:0a",
		DstMAC:    gwMAC, // 同网段直达：目的 MAC 就是网关的网卡
		FirstSeen: t0, LastSeen: t0.Add(30 * time.Second),
		BytesUp: 3000, BytesDown: 6000, Packets: 20,
	}
	// 经 NAT 出去之后的一段：源地址是出口地址，源 MAC 是网关自己的
	nat := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.8.9.2", DstIP: "10.8.9.20", SrcPort: 51000, DstPort: 443, Proto: "tcp"},
		MAC:       gwMAC,
		FirstSeen: t0.Add(time.Minute), LastSeen: t0.Add(2 * time.Minute),
		BytesUp: 40000, BytesDown: 80000, Packets: 60,
	}
	// 上网：目的在内网之外，这才是"它在给全网做首跳转发"的证据
	web := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.8.1.10", DstIP: "198.51.100.20", SrcPort: 40002, DstPort: 443, Proto: "tcp"},
		MAC:       "02:00:00:00:00:0a",
		DstMAC:    gwMAC,
		FirstSeen: t0.Add(3 * time.Minute), LastSeen: t0.Add(4 * time.Minute),
		BytesUp: 20000, BytesDown: 90000, Packets: 80,
	}
	return []*model.Session{dns, nat, web}
}

func TestGatewayIdentityConvergesRegardlessOfOrder(t *testing.T) {
	orders := map[string][]int{
		"先内网后出口": {0, 1, 2},
		"先出口后内网": {2, 1, 0},
		"出口夹在中间": {0, 2, 1},
	}
	for name, order := range orders {
		order := order
		t.Run(name, func(t *testing.T) {
			base := time.Now().Truncate(time.Second)
			sessions := gwSessions(base)
			e := New(model.SystemConfig{AggregateThreshold: 1000, AgingSeconds: 86400})
			for _, i := range order {
				e.Ingest(sessions[i])
			}
			snap := e.Snapshot()

			var gw []model.Node
			for _, n := range snap.Nodes {
				if n.MAC == gwMAC {
					gw = append(gw, n)
				}
			}
			if len(gw) != 1 {
				t.Fatalf("同一个 MAC 应该只有一个节点，实际 %d 个：%+v", len(gw), gw)
			}
			n := gw[0]
			if len(n.IPs) != 2 || n.IPs[0] != "10.8.1.1" || n.IPs[1] != "10.8.9.2" {
				t.Fatalf("网关应同时带内网口与出口口地址，实际 %v", n.IPs)
			}
			if !contains(n.Roles, RoleGateway) {
				t.Fatalf("网关没被识别成 %s，实际 roles=%v", RoleGateway, n.Roles)
			}
			// IP 只能有一个归属：分裂时最常见的样子是"两个节点都写着 10.8.1.1"
			owners := 0
			for _, other := range snap.Nodes {
				if contains(other.IPs, "10.8.1.1") {
					owners++
				}
			}
			if owners != 1 {
				t.Fatalf("10.8.1.1 应只属于 1 个节点，实际 %d 个", owners)
			}
		})
	}
}

// TestGatewayWithoutIPKeepsShell 只有 MAC、没有任何 IP 的网关仍然要在图上。
//
// 这是现场最常见的一种：局域网探针只看得到"所有人上网都发给这个 MAC"，
// 从来看不到它的 IP（没人连它的管理口、它也不当 DNS）。丢掉它，图上就是
// 一台台主机直连公网，中间那一跳凭空消失。
func TestGatewayWithoutIPKeepsShell(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	s := &model.Session{
		FiveTuple: model.FiveTuple{SrcIP: "10.8.1.10", DstIP: "198.51.100.20", SrcPort: 40003, DstPort: 443, Proto: "tcp"},
		MAC:       "02:00:00:00:00:0a",
		DstMAC:    gwMAC,
		FirstSeen: base, LastSeen: base.Add(time.Minute),
		BytesUp: 10000, BytesDown: 30000, Packets: 50,
	}
	e := New(model.SystemConfig{AggregateThreshold: 1000, AgingSeconds: 86400})
	e.Ingest(s)

	var found *model.Node
	for _, n := range e.Snapshot().Nodes {
		if n.MAC == gwMAC {
			nn := n
			found = &nn
		}
	}
	if found == nil {
		t.Fatal("只有 MAC 的网关也必须建节点，否则出口在图上不存在")
	}
	if !contains(found.Roles, RoleGateway) {
		t.Fatalf("它被证明在给主机做首跳转发，应识别成 %s，实际 %v", RoleGateway, found.Roles)
	}
}
