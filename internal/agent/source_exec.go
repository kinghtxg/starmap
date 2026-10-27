package agent

import (
	"bytes"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// limitedBuffer 只保留前 n 字节：采集工具失败时通常在第一行说清原因，
// 而 stderr 可能因为重试刷屏写成几十兆。
type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max == 0 {
		l.max = 4096
	}
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buf.Bytes()
	if utf8.Valid(b) {
		return string(b)
	}
	// 中文 Windows 上 cmd.exe 和不少命令行工具的 stderr 是 GBK。
	// 直接当 UTF-8 打出来是一串乱码，等于没说——而这条信息恰恰是
	// "为什么抓不到包"的唯一线索。
	if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil {
		return string(dec)
	}
	return string(b)
}

// OpenExec 把外部命令写到 stdout 的 pcap 流当作采集源。
//
// 这条路径存在的意义：有些机器上装不了编译器，但可能已经有 tcpdump / dumpcap / tshark。
// 只要能往 stdout 吐 pcap，探针就能用它，而不需要为每个平台写一套原生采集。
//
//	-source "exec:tcpdump -i eth0 -w - -U"
//	-source "exec:/usr/sbin/dumpcap -i eth0 -w -"
func OpenExec(command string) (Source, error) {
	cmd, kill := shellCommand(command)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("接管命令输出失败: %w", err)
	}
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动采集命令失败: %w", err)
	}
	// 必须有人 Wait：否则子进程退出后留下僵尸，长时间跑会攒出一堆。
	go func() { _ = cmd.Wait() }()

	// 15s 内必须看到 pcap 头。tcpdump/dumpcap 都是启动即写全局头，
	// 超过这个时间还没数据，基本可以断定命令本身有问题，早点失败比挂着强。
	src, err := openStream("exec:"+command, stdout, func() error { kill(); return nil }, 15*time.Second)
	if err != nil {
		kill()
		if s := stderr.String(); s != "" {
			return nil, fmt.Errorf("%w（命令输出: %s）", err, s)
		}
		return nil, err
	}
	return src, nil
}
