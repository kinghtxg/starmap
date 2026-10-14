// Package web 内嵌前端静态资源（embed.FS），供 API 层托管。
package web

import "embed"

// FS 内嵌全部前端页面与静态资源。
//go:embed *.html assets
var FS embed.FS
