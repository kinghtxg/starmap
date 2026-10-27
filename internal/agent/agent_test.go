package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// collector 收上报的 flows，供断言。
type collector struct {
	mu    sync.Mutex
	flows []Flow
	posts int
}

func (c *collector) snapshot() ([]Flow, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Flow(nil), c.flows...), c.posts
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	t.Helper()
	c := &collector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.flows = append(c.flows, rep.Flows...)
		c.posts++
		c.mu.Unlock()
		_, _ = w.Write([]byte(`{"accepted":1,"new_events":0}`))
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func pcapPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "out", name))
	if err != nil {
		t.Fatalf("解析路径失败: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("测试数据缺失 %s: %v", p, err)
	}
	return p
}

// TestRunOnceReplay 回放一份 pcap，端到端验证"采集→聚合→上报"这条链。
//
// 断言的不只是"有数据到"，还包括指纹字段（SNI）：这条链上任何一环把字段丢掉，
// 服务端规则都会静默失效，而前面的每一步看起来都正常。
func TestRunOnceReplay(t *testing.T) {
	c, srv := newCollector(t)
	src, err := OpenFile(pcapPath(t, "frp_tunnel.pcap"))
	if err != nil {
		t.Fatalf("打开 pcap 失败: %v", err)
	}
	err = Run(context.Background(), Config{
		Server:   srv.URL,
		ProbeID:  "p-test",
		Location: "单元测试",
		Once:     true,
		// 间隔拉长，逼着走"源结束 → 收尾 flush"这条路径（探针回放的真实用法）。
		Interval: time.Hour,
		Logger:   quietLog(),
	}, src)
	if err != nil {
		t.Fatalf("Run 返回错误: %v", err)
	}

	flows, posts := c.snapshot()
	if posts == 0 {
		t.Fatal("服务端一次上报都没收到")
	}
	if len(flows) != 1 {
		t.Fatalf("收到 %d 条会话, 期望 1（与直接上传 pcap 的 sessions 数一致）", len(flows))
	}
	f := flows[0]
	if f.SrcIP == "" || f.DstIP == "" {
		t.Errorf("五元组缺失: %+v", f)
	}
	if f.LastSeen == "" || f.FirstSeen == "" {
		t.Errorf("时间戳缺失: %+v", f)
	}
	if f.Location != "单元测试" {
		t.Errorf("location = %q, 期望沿用探针配置", f.Location)
	}
	if f.SNI == "" && f.JA3 == "" && f.HTTPHost == "" {
		t.Errorf("指纹全部为空——frp 规则会失效: %+v", f)
	}
}

// TestRunDryRunSendsNothing dry-run 只统计，不碰网络。
func TestRunDryRunSendsNothing(t *testing.T) {
	c, srv := newCollector(t)
	src, err := OpenFile(pcapPath(t, "clash_proxy.pcap"))
	if err != nil {
		t.Fatalf("打开 pcap 失败: %v", err)
	}
	if err := Run(context.Background(), Config{
		Server: srv.URL, ProbeID: "p", DryRun: true, Once: true,
		Interval: time.Hour, Logger: quietLog(),
	}, src); err != nil {
		t.Fatalf("Run 返回错误: %v", err)
	}
	if _, posts := c.snapshot(); posts != 0 {
		t.Fatalf("dry-run 竟然发了 %d 次上报", posts)
	}
}

// TestRunStopsOnContextCancel 长跑模式：ctx 取消后必须连同采集协程一起收尾，
// 不能留下还在读 fd 的协程（退出时进程会卡住或崩溃）。
func TestRunStopsOnContextCancel(t *testing.T) {
	_, srv := newCollector(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("建管道失败: %v", err)
	}
	// 先写一个合法 pcap 头，让 openStream 判定成功；之后不再写任何数据，
	// 模拟"网卡上暂时没流量"的真实状态。
	srcFile, err := os.ReadFile(pcapPath(t, "frp_tunnel.pcap"))
	if err != nil {
		t.Fatalf("读测试数据失败: %v", err)
	}
	if _, err := pw.Write(srcFile[:24]); err != nil {
		t.Fatalf("写 pcap 头失败: %v", err)
	}

	src, err := openStream("pipe", pr, func() error { return pw.Close() }, 0)
	if err != nil {
		t.Fatalf("构造采集源失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Server: srv.URL, ProbeID: "p", Interval: 20 * time.Millisecond, Logger: quietLog(),
		}, src)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run 返回错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后 Run 5s 内没有退出")
	}
}

// TestOpenFileMissing 文件不存在要立刻报错，而不是构造出一个"能跑但永远读不到数据"的源。
func TestOpenFileMissing(t *testing.T) {
	if _, err := OpenFile(filepath.Join(t.TempDir(), "nope.pcap")); err == nil {
		t.Fatal("打开不存在的文件应报错")
	}
}

// TestOpenStreamRejectsGarbage 采集命令吐了非 pcap 内容（比如权限不足时的报错文本）
// 必须在这里挡住。放过去的话，探针会"正常运行"却永远没有数据。
func TestOpenStreamRejectsGarbage(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("建管道失败: %v", err)
	}
	go func() {
		_, _ = pw.Write([]byte("tcpdump: eth0: You don't have permission to capture on that device"))
		_ = pw.Close()
	}()
	if _, err := openStream("garbage", pr, nil, 0); err == nil {
		t.Fatal("非 pcap 内容应报错")
	} else if !strings.Contains(err.Error(), "魔数") {
		t.Fatalf("错误信息应指出魔数不匹配，实际: %v", err)
	}
}

// TestPeekHeaderTimeout 采集命令启动成功但一直不输出时，不能无限等。
func TestPeekHeaderTimeout(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("建管道失败: %v", err)
	}
	defer pw.Close()
	defer pr.Close()
	start := time.Now()
	_, err = openStream("silent", pr, nil, 100*time.Millisecond)
	if err == nil {
		t.Fatal("应当超时失败")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("超时保护没生效，等了 %s", d)
	}
}

// TestOpenExecReplay 用外部命令吐 pcap 也能采集（没有原生后端的机器走这条）。
func TestOpenExecReplay(t *testing.T) {
	p := pcapPath(t, "multi_net.pcap")
	cmd := `cat "` + p + `"`
	if runtime.GOOS == "windows" {
		cmd = `type "` + p + `"`
	}
	src, err := OpenExec(cmd)
	if err != nil {
		t.Fatalf("OpenExec 失败: %v", err)
	}
	defer src.Close()

	n := 0
	timeout := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-src.Frames():
			if !ok {
				if n == 0 {
					t.Fatal("一帧都没读到")
				}
				return
			}
			n++
		case <-timeout:
			t.Fatalf("10s 内只读到 %d 帧", n)
		}
	}
}

// TestOpenExecFailsFast 命令立刻失败（工具没装/参数错）时要快速报错，
// 而不是卡在那里等 15s 超时。
func TestOpenExecFailsFast(t *testing.T) {
	cmd := "false"
	if runtime.GOOS == "windows" {
		cmd = "exit 1"
	}
	start := time.Now()
	if _, err := OpenExec(cmd); err == nil {
		t.Fatal("命令不输出 pcap 应报错")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("失败用了 %s，太慢", d)
	}
}

// TestOpenStreamPcapng pcapng 也要认。dumpcap 默认产 pcapng，
// 只认 pcap 魔数会让"用 dumpcap 抓的包回放不了"这种问题在很晚才暴露。
func TestOpenStreamPcapng(t *testing.T) {
	// 造一份最小的 pcapng：一个接口 + 一个报文。
	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("创建 pcapng 写入器失败: %v", err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Now(), CaptureLength: 4, Length: 4,
	}, []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("写 pcapng 失败: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("刷 pcapng 失败: %v", err)
	}

	src, err := openStream("ng", bytes.NewReader(buf.Bytes()), nil, 0)
	if err != nil {
		t.Fatalf("解析 pcapng 失败: %v", err)
	}
	defer src.Close()
	if src.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("链路类型 = %v", src.LinkType())
	}
	select {
	case f, ok := <-src.Frames():
		if !ok {
			t.Fatal("帧通道提前关闭")
		}
		if len(f.Data) != 4 {
			t.Errorf("帧长度 = %d, 期望 4", len(f.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("2s 内没读到帧")
	}
}

// TestConfigNormalize 默认值错了会让探针"跑起来但报错/不报"，
// 例如间隔为 0 时 ticker 直接 panic。
func TestConfigNormalize(t *testing.T) {
	var c Config
	c.normalize()
	if c.Server == "" || c.ProbeID == "" {
		t.Errorf("服务端/探针标识未兜底: %+v", c)
	}
	if c.Interval <= 0 || c.Batch <= 0 || c.Buffer <= 0 {
		t.Errorf("间隔/批次/缓冲未兜底: %+v", c)
	}
	if c.LongConnSeconds <= 0 || c.HeartbeatMaxBytes <= 0 {
		t.Errorf("长连接阈值未兜底: %+v", c)
	}
	if c.Logger == nil {
		t.Error("Logger 未兜底")
	}
}

// TestRunNilSource 没有采集源时立刻报错，不能起个空转的循环。
func TestRunNilSource(t *testing.T) {
	if err := Run(context.Background(), Config{Logger: quietLog()}, nil); !errors.Is(err, ErrNoSource) {
		t.Fatalf("nil 源应返回 ErrNoSource, 实际 %v", err)
	}
}
