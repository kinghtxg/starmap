//go:build ignore

// StarMap 政务网探针模拟器
//
// 在没有真实探针/镜像流量的环境（如家庭开发机）下，模拟多探针上报，
// 覆盖政务网典型场景，用于验证与演示 StarMap 的被动分析能力。
//
// 用法：
//
//	go run testdata/simprobe.go                       # 默认推送到 http://127.0.0.1:18080
//	go run testdata/simprobe.go -server http://x:8080 # 指定服务地址
//	go run testdata/simprobe.go -rounds 5 -interval 3s # 持续 5 轮，每轮间隔 3 秒
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// flow 探针上报的会话（与 server.probeFlow 字段一致）
type flow struct {
	SrcIP               string `json:"src_ip"`
	DstIP               string `json:"dst_ip"`
	SrcPort             int    `json:"src_port"`
	DstPort             int    `json:"dst_port"`
	Proto               string `json:"proto"`
	MAC                 string `json:"mac,omitempty"`
	BytesUp             int64  `json:"bytes_up"`
	BytesDown           int64  `json:"bytes_down"`
	Packets             int64  `json:"packets"`
	SNI                 string `json:"sni,omitempty"`
	HTTPHost            string `json:"http_host,omitempty"`
	JA3                 string `json:"ja3,omitempty"`
	JA4                 string `json:"ja4,omitempty"`
	IsLongConn          bool   `json:"is_long_conn,omitempty"`
	HeartbeatIntervalMs int64  `json:"heartbeat_interval_ms,omitempty"`
	FirstSeen           string `json:"first_seen"`
	LastSeen            string `json:"last_seen"`
}

type report struct {
	ProbeID  string `json:"probe_id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Ts       string `json:"ts"`
	Flows    []flow `json:"flows"`
}

// Go-TLS 指纹（与 detect 包 goTLSJA3 / goTLSJA4Prefixes 一致，确保能触发规则）
const (
	goJA3 = "fd8b3113a5a6c8c9f8b07b4e80b04d0e"
	goJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
)

var now = time.Now()

// mkFlow 构造一条上报会话；dur 为会话时长（0 表示默认 30 分钟长会话）。
func mkFlow(src, dst, mac string, sport, dport int, up, down int64, dur time.Duration, f flow) flow {
	f.SrcIP = src
	f.DstIP = dst
	f.SrcPort = sport
	f.DstPort = dport
	f.Proto = "tcp"
	f.MAC = mac
	f.BytesUp = up
	f.BytesDown = down
	f.Packets = 20 + rand.Int63n(80)
	if dur <= 0 {
		dur = 30 * time.Minute
	}
	start := now.Add(-dur)
	f.FirstSeen = start.Format(time.RFC3339)
	f.LastSeen = now.Format(time.RFC3339)
	return f
}

// 场景 1：政务内网核心段（10.10.0.0/16）—— 正常办公 + 一台疑似 frp 隧道
func probeGovInternal() report {
	var flows []flow
	base := "10.10.1."
	// 5 台正常办公终端访问内网 OA 服务器
	for i := 10; i < 15; i++ {
		ip := base + fmt.Sprint(i)
		mac := fmt.Sprintf("02:00:0a:01:%02d:00", i)
		flows = append(flows, mkFlow(ip, "10.10.1.100", mac, 40000+i, 80,
			2000+rand.Int63n(3000), 5000+rand.Int63n(8000), 0, flow{}))
	}
	// OA 服务器被多台终端访问（横向流量）
	for i := 10; i < 15; i++ {
		flows = append(flows, mkFlow("10.10.1.100", base+fmt.Sprint(i), "02:00:0a:01:64:00",
			80, 40000+i, 5000, 2000, 0, flow{}))
	}
	// ★ 疑似 frp 内网穿透：Go-TLS 指纹 + 长连接保活 + 周期心跳（三中三 → high）
	flows = append(flows, mkFlow("10.10.1.66", "203.0.113.77", "02:00:0a:01:66:00",
		51000, 7000, 1200, 900, 2*time.Hour, flow{
			JA3: goJA3, JA4: goJA4,
			IsLongConn:          true,
			HeartbeatIntervalMs: 30000,
		}))
	return report{
		ProbeID:  "probe-gov-internal",
		Name:     "政务内网核心探针",
		Location: "政务内网-核心段",
		Ts:       now.Format(time.RFC3339),
		Flows:    flows,
	}
}

// 场景 2：政务外网段（172.16.0.0/12）—— 正常上网 + 一台疑似 clash 代理
func probeGovExternal() report {
	var flows []flow
	base := "172.16.5."
	// 3 台正常终端访问互联网
	for i := 10; i < 13; i++ {
		ip := base + fmt.Sprint(i)
		mac := fmt.Sprintf("02:00:ac:05:%02d:00", i)
		flows = append(flows, mkFlow(ip, "198.51.100.20", mac, 42000+i, 443,
			1500, 9000, 0, flow{SNI: "www.gov-example.cn"}))
	}
	// ★ 疑似 clash 代理：随机高熵 SNI + 高频短间隔外联 + 陌生目的分散在多个公网 /24
	//   触发条件（detect/clash.go）：随机 SNI ≥1 且 短会话 ≥10 且 不同公网 /24 ≥5
	clashDsts := []string{
		"8.8.8.10", "8.8.8.20", // 8.8.8.0/24
		"1.1.1.10", "1.1.1.20", // 1.1.1.0/24
		"104.16.1.10", "104.16.1.20", // 104.16.1.0/24
		"151.101.1.10", "151.101.1.20", // 151.101.1.0/24
		"13.107.1.10", "13.107.1.20", // 13.107.1.0/24
		"52.94.1.10", "52.94.1.20", // 52.94.1.0/24
	}
	for i, dst := range clashDsts {
		// 短会话：时长 5~20 秒（< clashShortConnSec=30s 才算短连接）
		short := time.Duration(5+rand.Intn(15)) * time.Second
		// 随机高熵 SNI：判定取"倒数第二个标签"（域名主体），需 ≥10 字符且香农熵 >3.5
		// 故构造 <16位随机串>.com，而非 xxx.example.com（主体 example 仅 7 字符不达标）
		flows = append(flows, mkFlow("172.16.5.20", dst, "02:00:ac:05:14:00",
			43000+i, 443, 800, 1500, short, flow{
				SNI: fmt.Sprintf("%s.com", randStr(16)),
			}))
	}
	return report{
		ProbeID:  "probe-gov-external",
		Name:     "政务外网探针",
		Location: "政务外网-互联网出口区",
		Ts:       now.Format(time.RFC3339),
		Flows:    flows,
	}
}

// 场景 3：★ 一机两网违规 —— 同一台设备（同 MAC）同时接入政务内网与政务外网
// 这是政务网监管红线，应触发 multi_net（网段维度 /24 判定）
func probeViolationDualNet() report {
	const mac = "02:00:de:ad:01:01" // 同一块网卡
	flows := []flow{
		// 该设备在政务内网段
		mkFlow("10.10.1.50", "10.10.1.100", mac, 44001, 80, 3000, 6000, 0, flow{}),
		// 同一块网卡同时出现在政务外网段（/24 不同 → 一机两网）
		mkFlow("172.16.5.50", "198.51.100.20", mac, 44002, 443, 2500, 7000, 0,
			flow{SNI: "oa.gov-example.cn"}),
	}
	return report{
		ProbeID:  "probe-gov-internal",
		Name:     "政务内网核心探针",
		Location: "政务内网-核心段",
		Ts:       now.Format(time.RFC3339),
		Flows:    flows,
	}
}

// 场景 4：账外机（未纳管设备）—— 一台未在资产台账内的主机，长期在线
func probeUnmanaged() report {
	flows := []flow{
		mkFlow("10.10.1.200", "10.10.1.100", "02:00:0a:01:c8:00", 45001, 445,
			4000, 3000, 0, flow{}),
		mkFlow("10.10.1.200", "198.51.100.99", "02:00:0a:01:c8:00", 45002, 443,
			1200, 2500, 0, flow{SNI: "update.example.com"}),
	}
	return report{
		ProbeID:  "probe-gov-internal",
		Name:     "政务内网核心探针",
		Location: "政务内网-核心段",
		Ts:       now.Format(time.RFC3339),
		Flows:    flows,
	}
}

func randStr(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rand.Intn(len(cs))]
	}
	return string(b)
}

func post(server string, r report) (int, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	resp, err := http.Post(server+"/api/ingest/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func main() {
	server := flag.String("server", "http://127.0.0.1:18080", "StarMap 服务地址")
	rounds := flag.Int("rounds", 1, "上报轮次")
	interval := flag.Duration("interval", 2*time.Second, "轮次间隔")
	flag.Parse()

	fmt.Printf("=== StarMap 政务网探针模拟器 ===\n服务: %s\n\n", *server)

	scenes := []struct {
		name string
		gen  func() report
	}{
		{"政务内网核心段（正常办公 + frp 隧道）", probeGovInternal},
		{"政务外网段（正常上网 + clash 代理）", probeGovExternal},
		{"★ 一机两网违规（同 MAC 跨两个 /24）", probeViolationDualNet},
		{"账外机（未纳管设备）", probeUnmanaged},
	}

	for round := 1; round <= *rounds; round++ {
		if *rounds > 1 {
			fmt.Printf("--- 第 %d/%d 轮 ---\n", round, *rounds)
		}
		for _, sc := range scenes {
			r := sc.gen()
			code, err := post(*server, r)
			if err != nil {
				fmt.Printf("  [FAIL] %s: %v\n", sc.name, err)
				continue
			}
			if code != 200 {
				fmt.Printf("  [FAIL] %s: HTTP %d\n", sc.name, code)
				continue
			}
			fmt.Printf("  [OK] %-42s 探针=%s 位置=%s flows=%d\n",
				sc.name, r.ProbeID, r.Location, len(r.Flows))
		}
		if round < *rounds {
			time.Sleep(*interval)
		}
	}

	fmt.Printf("\n完成。打开 %s 查看拓扑、资产库与风险事件。\n", *server)
	if *rounds == 1 {
		fmt.Println("提示：用 -rounds N -interval 3s 可持续模拟探针在线上报。")
	}
	os.Exit(0)
}
