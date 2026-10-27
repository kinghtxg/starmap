package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"starmap/internal/config"
	"starmap/internal/detect"
	"starmap/internal/model"
	"starmap/internal/parser"
	"starmap/internal/probe"
	"starmap/internal/review"
	"starmap/internal/store"
	"starmap/internal/topology"
)

func testCfg() model.SystemConfig {
	return model.SystemConfig{
		AgingSeconds: 86400, AggregateThreshold: 20,
		NoiseBytes: 400, NoisePackets: 4, NoiseDurationSec: 2,
		ReverseProxyHosts: 10, LongConnSeconds: 3600, HeartbeatMaxBytes: 64,
		ListenAddr: ":0", DBPath: ":memory:",
	}
}

func newTestRouter(t *testing.T, cfg model.SystemConfig) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := topology.New(cfg)
	agg := parser.NewAggregator(cfg.LongConnSeconds, cfg.HeartbeatMaxBytes)
	det := detect.New(st, eng, cfg)
	det.SessionsFunc = agg.Sessions
	det.LearningPeriod = 0
	rvw := review.New(st, eng)
	scanner := probe.New(eng)
	scanner.SetEnabled(cfg.ProbeEnabled)
	return NewRouter(Deps{
		Store: st, Engine: eng, Detector: det, Reviewer: rvw, Scanner: scanner,
		Cfg: config.NewBox(cfg), Aggregator: agg,
	}), st
}

func doReq(t *testing.T, h http.Handler, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// ---------- 合成 PCAP ----------

var base = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)

func clientHello(sni string) []byte {
	var body []byte
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	u24 := func(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	var ext []byte
	if sni != "" {
		var snib []byte
		snib = append(snib, u16(len(sni)+3)...)
		snib = append(snib, 0x00)
		snib = append(snib, u16(len(sni))...)
		snib = append(snib, sni...)
		ext = append(ext, 0x00, 0x00)
		ext = append(ext, u16(len(snib))...)
		ext = append(ext, snib...)
	}
	body = append(body, u16(len(ext))...)
	body = append(body, ext...)
	hs := append([]byte{0x01}, u24(len(body))...)
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...)
	return append(rec, hs...)
}

type pktSpec struct {
	ts      time.Time
	payload []byte
	length  int
}

// buildFRPPCAP 合成 FRP 特征 PCAP：长连接（>1h 时间戳）+ 周期小包心跳 + TLS hello。
func buildFRPPCAP(t *testing.T, srcIP string, srcMAC string, sport uint16) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	dstIP := "203.0.113.60"
	dstMAC := "02:00:00:00:00:01"
	write := func(ts time.Time, payload []byte, l int) {
		eth := &layers.Ethernet{SrcMAC: mustMAC(srcMAC), DstMAC: mustMAC(dstMAC), EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{0, 0, 0, 0}, DstIP: []byte{0, 0, 0, 0}, Protocol: layers.IPProtocolTCP}
		ip.SrcIP = parseIPv4(srcIP)
		ip.DstIP = parseIPv4(dstIP)
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: 7000, Seq: 1, ACK: true, PSH: payload != nil}
		tcp.SetNetworkLayerForChecksum(ip)
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		b := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(b, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		data := b.Bytes()
		if l > len(data) {
			data = append(data, make([]byte, l-len(data))...)
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	// TLS ClientHello
	write(base, clientHello("tunnel.example.com"), 0)
	// 周期小包心跳（间隔 30s，payload < 64B）
	for i := 1; i <= 4; i++ {
		write(base.Add(time.Duration(i)*30*time.Second), []byte("ping"), 0)
	}
	// 2h 后的大包 → 长连接 + 总字节超降噪阈值
	write(base.Add(2*time.Hour), make([]byte, 600), 0)
	return buf.Bytes()
}

func mustMAC(s string) []byte {
	var m [6]byte
	var v []byte
	for _, part := range bytes.Split([]byte(s), []byte(":")) {
		n, _ := strconvParseHex(string(part))
		v = append(v, byte(n))
	}
	copy(m[:], v)
	return m[:]
}

func strconvParseHex(s string) (int, error) {
	n := 0
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n |= int(c - '0')
		case c >= 'a' && c <= 'f':
			n |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n |= int(c-'A') + 10
		}
	}
	return n, nil
}

func parseIPv4(s string) []byte {
	var out [4]byte
	i := 0
	n := 0
	for _, c := range s {
		if c == '.' {
			out[i] = byte(n)
			i++
			n = 0
		} else {
			n = n*10 + int(c-'0')
		}
	}
	out[i] = byte(n)
	return out[:]
}

func uploadPCAP(t *testing.T, h http.Handler, data []byte, filename string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest("POST", "/api/ingest/pcap", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// ---------- 测试 ----------

func TestHealth(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, "GET", "/api/health", nil, nil)
	if w.Code != 200 {
		t.Fatalf("health %d", w.Code)
	}
}

// 集成：上传 FRP 特征 PCAP → 事件生成 → 拓扑快照 → review 状态流转（ACCEPTANCE 11.3）
func TestPCAPIngestToEventToReview(t *testing.T) {
	h, st := newTestRouter(t, testCfg())
	pcap := buildFRPPCAP(t, "192.168.1.10", "aa:bb:cc:00:00:01", 5000)

	w := uploadPCAP(t, h, pcap, "frp.pcap")
	if w.Code != 200 {
		t.Fatalf("上传失败 %d: %s", w.Code, w.Body.String())
	}

	// 事件
	w = doReq(t, h, "GET", "/api/events?status=pending&type=frp", nil, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var evs []map[string]any
	json.Unmarshal(w.Body.Bytes(), &evs)
	if len(evs) != 1 {
		t.Fatalf("应产生 1 个 frp pending 事件，实际 %d", len(evs))
	}
	ev := evs[0]
	if ev["Level"] != "mid" && ev["Level"] != "high" {
		t.Fatalf("事件级别异常: %v", ev["Level"])
	}
	if ev["Evidence"].(map[string]any)["heartbeat_interval_ms"] == "" {
		t.Fatal("证据应含心跳间隔")
	}

	// 拓扑快照：节点 + 外部聚合节点 + 边，节点风险联动
	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	var snap map[string]any
	json.Unmarshal(w.Body.Bytes(), &snap)
	nodes := snap["Nodes"].([]any)
	if len(nodes) < 2 {
		t.Fatalf("拓扑应至少 2 节点: %s", w.Body.String())
	}
	var srcNode map[string]any
	for _, n := range nodes {
		nn := n.(map[string]any)
		for _, ip := range nn["IPs"].([]any) {
			if ip == "192.168.1.10" {
				srcNode = nn
			}
		}
	}
	if srcNode == nil {
		t.Fatal("拓扑缺少源节点")
	}
	if srcNode["RiskLevel"] != "mid" && srcNode["RiskLevel"] != "high" {
		t.Fatalf("事件后节点风险应联动，实际 %v", srcNode["RiskLevel"])
	}
	if len(snap["Edges"].([]any)) == 0 {
		t.Fatal("拓扑应有边")
	}

	// review：confirm → confirmed + 审计
	evID := int64(ev["ID"].(float64))
	w = doReq(t, h, "POST", "/api/events/"+itoa(evID)+"/review",
		map[string]string{"action": "confirm", "note": "确认", "reviewer": "admin"}, nil)
	if w.Code != 200 {
		t.Fatalf("review 失败: %s", w.Body.String())
	}
	var reviewed map[string]any
	json.Unmarshal(w.Body.Bytes(), &reviewed)
	if reviewed["Status"] != "confirmed" {
		t.Fatalf("状态应为 confirmed，实际 %v", reviewed["Status"])
	}
	logsW := doReq(t, h, "GET", "/api/audit", nil, nil)
	var logs []map[string]any
	json.Unmarshal(logsW.Body.Bytes(), &logs)
	found := false
	for _, l := range logs {
		if l["Action"] == "event_confirm" {
			found = true
		}
	}
	if !found {
		t.Fatal("审计日志缺少 event_confirm")
	}
	_ = st
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// 集成：白名单抑制（先加白再上传 → 无事件；加白后已有 pending 自动 false_positive）
func TestWhitelistSuppressionAPI(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	// 先加白
	w := doReq(t, h, "POST", "/api/whitelist", map[string]string{"Kind": "ip", "Value": "192.168.1.20", "Note": "t"}, nil)
	if w.Code != 201 {
		t.Fatalf("加白失败: %s", w.Body.String())
	}
	pcap := buildFRPPCAP(t, "192.168.1.20", "aa:bb:cc:00:00:02", 5001)
	if w := uploadPCAP(t, h, pcap, "frp2.pcap"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/events?type=frp", nil, nil)
	var evs []map[string]any
	json.Unmarshal(w.Body.Bytes(), &evs)
	if len(evs) != 0 {
		t.Fatalf("白名单命中不应产生事件: %v", evs)
	}

	// 删除白名单后可再次产生事件
	w = doReq(t, h, "GET", "/api/whitelist", nil, nil)
	var wl []map[string]any
	json.Unmarshal(w.Body.Bytes(), &wl)
	doReq(t, h, "DELETE", "/api/whitelist/"+itoa(int64(wl[0]["ID"].(float64))), nil, nil)
	pcap = buildFRPPCAP(t, "192.168.1.21", "aa:bb:cc:00:00:03", 5002)
	uploadPCAP(t, h, pcap, "frp3.pcap")
	w = doReq(t, h, "GET", "/api/events?status=pending&type=frp", nil, nil)
	evs = nil
	json.Unmarshal(w.Body.Bytes(), &evs)
	if len(evs) == 0 {
		t.Fatal("删除白名单后应产生事件")
	}

	// 已有 pending 事件：重新加白 → 自动 false_positive
	var target map[string]any
	for _, e := range evs {
		if e["Evidence"].(map[string]any)["src_ip"] == "192.168.1.21" {
			target = e
		}
	}
	if target == nil {
		t.Fatal("缺少 192.168.1.21 的 frp 事件")
	}
	evID := int64(target["ID"].(float64))
	nodeID := int64(target["NodeID"].(float64))
	w = doReq(t, h, "POST", "/api/whitelist", map[string]string{"Kind": "node", "Value": itoa(nodeID)}, nil)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["Suppressed"].(float64) < 1 {
		t.Fatal("加白应自动抑制已有 pending 事件")
	}
	w = doReq(t, h, "GET", "/api/events?status=false_positive", nil, nil)
	evs = nil
	json.Unmarshal(w.Body.Bytes(), &evs)
	found := false
	for _, e := range evs {
		if int64(e["ID"].(float64)) == evID {
			found = true
		}
	}
	if !found {
		t.Fatal("事件应自动转 false_positive")
	}
}

func TestProbeIngestAPI(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	// 非法负载 → 400
	w := doReq(t, h, "POST", "/api/ingest/probe", map[string]any{"foo": 1}, nil)
	if w.Code != 400 {
		t.Fatalf("非法负载应 400，实际 %d", w.Code)
	}
	// 合法上报（flows 形式）
	body := map[string]any{
		"probe_id": "probe-1",
		"ts":       base.Format(time.RFC3339),
		"flows": []map[string]any{{
			"src_ip": "172.16.1.5", "dst_ip": "172.16.1.6",
			"src_port": 40000, "dst_port": 80, "proto": "tcp",
			"bytes_up": 3000, "bytes_down": 8000, "packets": 40,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(30 * time.Second).Format(time.RFC3339),
		}},
	}
	w = doReq(t, h, "POST", "/api/ingest/probe", body, nil)
	if w.Code != 200 {
		t.Fatalf("探针上报失败 %d: %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	var snap map[string]any
	json.Unmarshal(w.Body.Bytes(), &snap)
	if len(snap["Nodes"].([]any)) < 2 || len(snap["Edges"].([]any)) == 0 {
		t.Fatalf("探针数据应进入拓扑: %s", w.Body.String())
	}
}

func TestProbeLocationIngest(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	body := map[string]any{
		"probe_id": "probe-3f",
		"name":     "3F机房探针",
		"location": "3F机房",
		"ts":       base.Format(time.RFC3339),
		"flows": []map[string]any{{
			"src_ip": "10.10.0.1", "dst_ip": "10.10.0.2",
			"src_port": 40000, "dst_port": 80, "proto": "tcp",
			"bytes_up": 5000, "bytes_down": 8000, "packets": 40,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(30 * time.Second).Format(time.RFC3339),
		}},
	}
	w := doReq(t, h, "POST", "/api/ingest/probe", body, nil)
	if w.Code != 200 {
		t.Fatalf("探针上报失败 %d: %s", w.Code, w.Body.String())
	}
	// 拓扑节点应带 location
	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	var snap map[string]any
	json.Unmarshal(w.Body.Bytes(), &snap)
	nodes := snap["Nodes"].([]any)
	found := false
	for _, n := range nodes {
		if nn, ok := n.(map[string]any); ok && nn["Location"] == "3F机房" {
			found = true
		}
	}
	if !found {
		t.Fatalf("节点应带 location=3F机房: %s", w.Body.String())
	}
	// 探针注册列表应包含该探针
	w = doReq(t, h, "GET", "/api/probes", nil, nil)
	var probes []map[string]any
	json.Unmarshal(w.Body.Bytes(), &probes)
	if len(probes) != 1 || probes[0]["location"] != "3F机房" {
		t.Fatalf("探针注册错误: %s", w.Body.String())
	}
}

// V1.4 P0 回归：聚合网段内的成员主机必须全部进资产库。
// 旧实现 syncAssets 遍历 Snapshot，而 Snapshot 会隐藏已聚合 /24 的成员，
// 导致"网段内超过聚合阈值的主机永远发现不了"（账外资产发现静默失效）。
func TestAssetSyncIncludesAggregatedMembers(t *testing.T) {
	cfg := testCfg()
	cfg.AggregateThreshold = 3 // 低阈值，5 台主机必然触发该 /24 聚合
	h, _ := newTestRouter(t, cfg)

	var flows []map[string]any
	for i := 1; i <= 5; i++ {
		flows = append(flows, map[string]any{
			"src_ip":     fmt.Sprintf("192.168.5.%d", i),
			"dst_ip":     "8.8.8.8",
			"src_port":   40000 + i,
			"dst_port":   443,
			"proto":      "tcp",
			"mac":        fmt.Sprintf("aa:bb:cc:70:00:%02d", i),
			"bytes_up":   5000,
			"bytes_down": 8000,
			"packets":    40,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(30 * time.Second).Format(time.RFC3339),
		})
	}
	w := doReq(t, h, "POST", "/api/ingest/probe", map[string]any{"probe_id": "p-agg", "flows": flows}, nil)
	if w.Code != 200 {
		t.Fatalf("探针上报失败 %d: %s", w.Code, w.Body.String())
	}

	w = doReq(t, h, "GET", "/api/assets", nil, nil)
	var assets []map[string]any
	json.Unmarshal(w.Body.Bytes(), &assets)
	if len(assets) < 5 {
		t.Fatalf("聚合网段内 5 台主机都应进资产库（实际 %d），说明仍被聚合隐藏", len(assets))
	}
	// 抽查：确认 5 个不同 IP 都在
	seen := map[string]bool{}
	for _, a := range assets {
		if ips, ok := a["ips"].([]any); ok {
			for _, ip := range ips {
				seen[fmt.Sprint(ip)] = true
			}
		}
	}
	for i := 1; i <= 5; i++ {
		want := fmt.Sprintf("192.168.5.%d", i)
		if !seen[want] {
			t.Fatalf("资产库缺少主机 %s（聚合成员仍被隐藏）", want)
		}
	}
}

// V1.4 网段清单：应返回全部已发现内网网段及每网段主机数/在线数
func TestSubnetsList(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	var flows []map[string]any
	add := func(ip, mac string) {
		flows = append(flows, map[string]any{
			"src_ip": ip, "dst_ip": "8.8.8.8",
			"src_port": 40000, "dst_port": 443, "proto": "tcp", "mac": mac,
			"bytes_up": 3000, "bytes_down": 6000, "packets": 30,
			"first_seen": base.Format(time.RFC3339),
			"last_seen":  base.Add(20 * time.Second).Format(time.RFC3339),
		})
	}
	// 网段 A：3 台；网段 B：2 台
	for i := 1; i <= 3; i++ {
		add(fmt.Sprintf("10.10.1.%d", i), fmt.Sprintf("aa:bb:cc:11:00:%02d", i))
	}
	for i := 1; i <= 2; i++ {
		add(fmt.Sprintf("172.16.5.%d", i), fmt.Sprintf("aa:bb:cc:22:00:%02d", i))
	}
	if w := doReq(t, h, "POST", "/api/ingest/probe",
		map[string]any{"probe_id": "p-sub", "flows": flows}, nil); w.Code != 200 {
		t.Fatalf("上报失败 %d", w.Code)
	}

	w := doReq(t, h, "GET", "/api/subnets", nil, nil)
	if w.Code != 200 {
		t.Fatalf("网段清单应 200，实际 %d", w.Code)
	}
	var subs []map[string]any
	json.Unmarshal(w.Body.Bytes(), &subs)
	if len(subs) != 2 {
		t.Fatalf("应返回 2 个网段，实际 %d: %s", len(subs), w.Body.String())
	}
	got := map[string]int{}
	for _, s := range subs {
		got[fmt.Sprint(s["cidr"])] = int(s["host_count"].(float64))
	}
	if got["10.10.1.0/24"] != 3 || got["172.16.5.0/24"] != 2 {
		t.Fatalf("网段主机数不符: %v", got)
	}
}

func TestProbeToken(t *testing.T) {
	cfg := testCfg()
	cfg.ProbeToken = "secret-token"
	h, _ := newTestRouter(t, cfg)
	body := map[string]any{"probe_id": "p1", "packets": []map[string]any{}}
	// 无 token → 401... packets 空会先 400；token 校验在前
	w := doReq(t, h, "POST", "/api/ingest/probe", body, nil)
	if w.Code != 401 {
		t.Fatalf("缺 token 应 401，实际 %d", w.Code)
	}
	// 正确 token（header）→ 400（空数据），说明通过校验
	w = doReq(t, h, "POST", "/api/ingest/probe", body, map[string]string{"X-Probe-Token": "secret-token"})
	if w.Code != 400 {
		t.Fatalf("token 正确应进入业务校验（400），实际 %d", w.Code)
	}
}

func TestProbeTriggerAPI(t *testing.T) {
	h, _ := newTestRouter(t, testCfg()) // probe_enabled=false
	w := doReq(t, h, "POST", "/api/probe/trigger", map[string]string{"type": "arp", "target": "192.168.1.1"}, nil)
	if w.Code != 403 {
		t.Fatalf("开关关闭应 403，实际 %d", w.Code)
	}
	// 开启后非法类型 → 400
	cfg := testCfg()
	cfg.ProbeEnabled = true
	h2, _ := newTestRouter(t, cfg)
	w = doReq(t, h2, "POST", "/api/probe/trigger", map[string]string{"type": "syn_scan", "target": "x"}, nil)
	if w.Code != 400 {
		t.Fatalf("非法类型应 400，实际 %d", w.Code)
	}
}

func TestDomainsCRUDAndNodeReassign(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	// 建域
	w := doReq(t, h, "POST", "/api/domains", map[string]any{"Name": "gov", "CIDRs": []string{"192.168.0.0/16"}, "Color": "#38BDF8"}, nil)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	// 注入流量
	body := map[string]any{"probe_id": "p", "flows": []map[string]any{{
		"src_ip": "192.168.5.5", "dst_ip": "8.8.8.8", "src_port": 40000, "dst_port": 443, "proto": "tcp",
		"bytes_up": 3000, "bytes_down": 8000, "packets": 40,
	}}}
	w = doReq(t, h, "POST", "/api/ingest/probe", body, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	var snap map[string]any
	json.Unmarshal(w.Body.Bytes(), &snap)
	for _, n := range snap["Nodes"].([]any) {
		nn := n.(map[string]any)
		for _, ip := range nn["IPs"].([]any) {
			if ip == "192.168.5.5" && nn["Domain"] != "gov" {
				t.Fatalf("节点域归属应为 gov，实际 %v", nn["Domain"])
			}
		}
	}
	// 改域 CIDR → 节点归属更新
	w = doReq(t, h, "GET", "/api/domains", nil, nil)
	var ds []map[string]any
	json.Unmarshal(w.Body.Bytes(), &ds)
	id := int64(ds[0]["ID"].(float64))
	doReq(t, h, "PUT", "/api/domains/"+itoa(id), map[string]any{"Name": "gov", "CIDRs": []string{"10.0.0.0/8"}, "Color": "#F87171"}, nil)
	w = doReq(t, h, "GET", "/api/topology", nil, nil)
	snap = nil
	json.Unmarshal(w.Body.Bytes(), &snap)
	for _, n := range snap["Nodes"].([]any) {
		nn := n.(map[string]any)
		for _, ip := range nn["IPs"].([]any) {
			if ip == "192.168.5.5" && nn["Domain"] == "gov" {
				t.Fatal("CIDR 修改后节点不应再归属 gov")
			}
		}
	}
}

func TestConfigGetPut(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, "GET", "/api/config", nil, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var cfg map[string]any
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg["probe_enabled"] != false || cfg["aggregate_threshold"].(float64) != 20 {
		t.Fatalf("配置字段异常: %v", cfg)
	}
	cfg["aggregate_threshold"] = 5
	cfg["probe_enabled"] = true
	w = doReq(t, h, "PUT", "/api/config", cfg, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/config", nil, nil)
	cfg = nil
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg["aggregate_threshold"].(float64) != 5 || cfg["probe_enabled"] != true {
		t.Fatalf("PUT 后配置未生效: %v", cfg)
	}
}

func TestBadPCAP(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := uploadPCAP(t, h, []byte("not a pcap file at all............"), "bad.pcap")
	if w.Code != 400 {
		t.Fatalf("损坏文件应 400，实际 %d", w.Code)
	}
}

func TestCaptureStatus(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	w := doReq(t, h, "GET", "/api/capture/status", nil, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	// 未配置网卡 → start 400
	w = doReq(t, h, "POST", "/api/capture/start", nil, nil)
	if w.Code != 400 && w.Code != 501 {
		t.Fatalf("无网卡配置应 400，实际 %d", w.Code)
	}
}

func TestStaticFiles(t *testing.T) {
	h, _ := newTestRouter(t, testCfg())
	for _, p := range []string{"/", "/index.html", "/assets/api.js", "/events.html"} {
		w := doReq(t, h, "GET", p, nil, nil)
		if w.Code != 200 {
			t.Fatalf("静态资源 %s 应 200，实际 %d", p, w.Code)
		}
	}
}
