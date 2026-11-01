package ingest

// OpenPCAPReader 的行为测试（multipart 上传走这条路）。
//
// 它做三件事：整个读进内存 → 落到临时文件 → 交给 OpenPCAPFile 解析。
// 值得钉住的是**临时文件的生命周期**：这条路径每次上传都会 os.CreateTemp，
// 清理只要漏一次，/tmp 就会被慢慢填满——而这类泄漏在功能上完全看不出来
// （上传照常成功、报文照常解析），只在某天磁盘满了才暴露。
//
// 另外它把整个 body 读进内存再写盘，所以调用方必须先过 bodyLimit 中间件
// （见 api/middleware_security.go 的白名单）。这里不代表可以随便灌。

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uploadTempFiles 列出 os.TempDir 下本函数创建的临时文件。
func uploadTempFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "starmap-upload-*"))
	if err != nil {
		t.Fatalf("列举临时文件失败: %v", err)
	}
	return matches
}

// TestOpenPCAPReaderParsesAndCleans 正常上传：报文能解析出来，临时文件读完即删。
func TestOpenPCAPReaderParsesAndCleans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "src.pcap")
	genTestPCAP(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读测试 pcap 失败: %v", err)
	}

	before := uploadTempFiles(t)

	src, err := OpenPCAPReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenPCAPReader 失败: %v", err)
	}
	var count, tcp int
	for info := range src {
		count++
		if info.Proto == "tcp" {
			tcp++
		}
		if info.SrcIP == "" {
			t.Fatal("IP 没解析出来")
		}
	}
	if count != 3 || tcp != 2 {
		t.Fatalf("报文数 = %d（tcp %d），期望 3（tcp 2）", count, tcp)
	}

	// range 退出时 goroutine 已经 return：它用
	//   defer close(out) / defer os.Remove(tmp)
	// 两个 defer 是 LIFO，所以 os.Remove 先于 close 执行。
	// 这个顺序是有意的——写反了 close 会先发生，消费者可能在删除前就走完了，
	// 于是这条断言会变成偶发失败。所以这里读完后立刻断言，不留缓冲时间。
	after := uploadTempFiles(t)
	if len(after) > len(before) {
		t.Fatalf("临时文件泄漏：上传前 %d 个，读完后 %d 个（新增 %v）",
			len(before), len(after), diffFiles(before, after))
	}
}

// TestOpenPCAPReaderBadInputCleans 解析失败时也必须清掉临时文件。
//
// 失败分支最容易漏清理：成功路径有人看，失败路径只在出错那天跑一次。
func TestOpenPCAPReaderBadInputCleans(t *testing.T) {
	before := uploadTempFiles(t)

	_, err := OpenPCAPReader(strings.NewReader("这不是一个 pcap 文件"))
	if err == nil {
		t.Fatal("非法内容应报错")
	}

	after := uploadTempFiles(t)
	if len(after) > len(before) {
		t.Fatalf("解析失败后残留临时文件：%v", diffFiles(before, after))
	}
}

func diffFiles(before, after []string) []string {
	seen := map[string]bool{}
	for _, f := range before {
		seen[f] = true
	}
	var out []string
	for _, f := range after {
		if !seen[f] {
			out = append(out, f)
		}
	}
	return out
}
