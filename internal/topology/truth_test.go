package topology_test

import (
	"testing"
	"time"

	"starmap/internal/model"
	"starmap/internal/simnet"
	"starmap/internal/topology"
	"starmap/test/truthcheck"
)

// 用自造真值校验拓扑引擎。
//
// 这里不测"某个函数返回什么"，而是测"引擎画出来的这张图，和真值差多少"。
// 两者的区别在于：前者只能防回归，后者能发现"整体看起来对、局部全错"的问题——
// 比如一机两网被拆成两台、一个会话被算两遍。
//
// 场景全部关闭聚合（阈值调高到 1000），这样校验器不需要复刻聚合算法就能直接比对；
// 聚合本身的正确性另有专门用例。
func TestTopologyAgainstGroundTruth(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, w := range simnet.All(42, now) {
		w := w
		t.Run(w.Name, func(t *testing.T) {
			cfg := model.SystemConfig{
				AgingSeconds:       86400,
				AggregateThreshold: 1000, // 关掉聚合，先看"个体"对不对
				NoiseBytes:         400,
				NoisePackets:       4,
				NoiseDurationSec:   2,
			}
			e := topology.New(cfg)
			for _, s := range w.Sessions() {
				s := s
				e.Ingest(&s)
			}

			snap := e.Snapshot()
			pairs := e.SnapshotEdgePairs()

			nodes := make([]truthcheck.Node, 0, len(snap.Nodes))
			for _, n := range snap.Nodes {
				nodes = append(nodes, truthcheck.Node{
					// Key 取 APINodeID 的同一命名空间（边的 Src/Dst 用的就是它），
					// 聚合节点是 subnet:/ext: 前缀，普通节点是内部 ID 的十进制串。
					Key:     topology.APINodeID(&n),
					NodeKey: n.NodeKey,
					IPs:     n.IPs, MAC: n.MAC,
					FirstSeen: n.FirstSeen, Ports: n.Ports,
					Labels: n.Labels, Members: n.Members,
				})
			}
			edges := make([]truthcheck.Edge, 0, len(pairs))
			for _, p := range pairs {
				edges = append(edges, truthcheck.Edge{
					Src: p.Src, Dst: p.Dst, Protocol: p.Protocol,
					Kind: p.Kind, Bytes: p.Bytes, FirstSeen: p.FirstSeen,
				})
			}

			rep := truthcheck.Check(w, nodes, edges)
			t.Log("\n" + rep.String())
			if !rep.Pass() {
				t.Errorf("%s：%d 项硬失败（详见日志）", w.Name, len(rep.Hard))
			}
		})
	}
}
