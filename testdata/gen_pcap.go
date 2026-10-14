//go:build ignore

// gen_pcap.go 生成 5 类场景的合成 PCAP 到 testdata/out/（SPEC §8 / ACCEPTANCE 11.1）。
// 用法：go run testdata/gen_pcap.go
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"starmap/testdata/pcapgen"
)

func main() {
	outDir := "testdata/out"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	for name, gen := range pcapgen.Scenarios() {
		data, err := gen()
		if err != nil {
			log.Fatalf("生成 %s 失败: %v", name, err)
		}
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-22s %8d bytes\n", path, len(data))
	}
}
