// Package version 版本信息单一来源。
//
// 之前版本号散落在 main.go 的日志字符串、api.Deps.Version、注释里，出现过多处
// "V1.0 / V1.1 / V1.2" 并存的情况 —— 用户报障时说的版本和代码里的对不上。
// 1.0.0 起，版本号只在这里定义，构建时用 ldflags 注入真实值：
//
//	go build -ldflags "-X starmap/internal/version.Version=1.3.1 \
//	                    -X starmap/internal/version.Commit=$(git rev-parse --short HEAD)"
package version

import "fmt"

// 构建时通过 -ldflags 覆盖；不改代码也能出带版本号的二进制。
var (
	// Version 语义化版本号（MAJOR.MINOR.PATCH）。
	Version = "1.3.1"
	// Commit 构建所对应的 git 提交短哈希。
	Commit = "dev"
	// BuildTime 构建时间（RFC3339），留空表示未注入。
	BuildTime = ""
)

// String 返回版本号，用于 API /health 与界面展示。
func String() string {
	return Version
}

// Full 返回 "版本+提交"，用于启动日志与排障。
func Full() string {
	if Commit == "" || Commit == "dev" {
		return Version
	}
	return fmt.Sprintf("%s+%s", Version, Commit)
}
