package main

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"starmap/internal/model"
)

// 本文件是「配置项一致性」的守卫测试，专门防一类复发问题：
//
//	后台改完 → 运行正常 → 重启又变回去
//
// 这类 bug 只在重启时暴露，开发时几乎撞不到，1.3.0 的 event_retention_days 就踩了。
// 根因是三处清单各自维护、没有交叉校验：
//
//	① PUT /api/config 接受哪些键      （internal/api/server.go  putConfig）
//	② 启动时从哪里恢复（saved.*）      （cmd/starmap/main.go     mergeRuntimeConfig）
//	③ model.SystemConfig 有哪些字段
//
// mergeRuntimeConfig 的注释里写着"凡是通过 PUT /api/config 能被改的字段，这里都必须恢复"，
// 但注释拦不住人。这里把它变成可执行的断言：新增配置项时如果漏了任何一处，测试立刻红。

// configKeyToField 是「请求键 → SystemConfig 字段」的唯一映射。
//
// 新增配置项时要同时改三个地方（putConfig 解析、mergeRuntimeConfig 恢复、本表登记），
// 少改任何一处都会让本测试失败。这不是冗余，是让漏改在 CI 里当场暴露，
// 而不是等用户重启后发一贴 issue。
var configKeyToField = map[string]string{
	// 被动测绘与降噪
	"aging_seconds":       "AgingSeconds",
	"aggregate_threshold": "AggregateThreshold",
	"noise_bytes":         "NoiseBytes",
	"noise_packets":       "NoisePackets",
	"noise_duration_sec":  "NoiseDurationSec",
	"reverse_proxy_hosts": "ReverseProxyHosts",
	"long_conn_seconds":   "LongConnSeconds",
	"heartbeat_max_bytes": "HeartbeatMaxBytes",
	// 数据接入
	"probe_enabled":      "ProbeEnabled",
	"probe_token":        "ProbeToken",
	"capture_enabled":    "CaptureEnabled",
	"capture_interfaces": "CaptureInterfaces",
	"capture_bpf":        "CaptureBPF",
	// 保留期
	"audit_retention_days": "AuditRetentionDays",
	"event_retention_days": "EventRetentionDays",
	// 资产库
	"unarchived_offline_hours": "UnarchivedOfflineHours",
	"archive_offline_seconds":  "ArchiveOfflineSeconds",
	// 主动端口扫描（nmap 路径）
	"scan_ports": "ScanPorts",
	"scan_rate":  "ScanRate",
	// 自动发现（V1.4 / V1.5）
	"auto_discovery_enabled":           "AutoDiscoveryEnabled",
	"auto_discovery_sec":               "AutoDiscoverySec",
	"auto_discovery_method":            "AutoDiscoveryMethod",
	"auto_discovery_cidrs":             "AutoDiscoveryCIDRs",
	"auto_discovery_follow_discovered": "AutoDiscoveryFollowDiscovered",
	"auto_discovery_max_cidrs":         "AutoDiscoveryMaxCIDRs",
	"auto_discovery_exclude_cidrs":     "AutoDiscoveryExcludeCIDRs",
	// 主动发现（1.2）
	"discover_enabled":          "DiscoverEnabled",
	"discover_profile":          "DiscoverProfile",
	"discover_rate_pps":         "DiscoverRatePPS",
	"discover_concurrency":      "DiscoverConcurrency",
	"discover_timeout_ms":       "DiscoverTimeoutMS",
	"discover_fingerprint":      "DiscoverFingerprint",
	"discover_max_fingerprints": "DiscoverMaxFP",
	"discover_window":           "DiscoverWindow",
	"discover_sec":              "DiscoverSec",
	"discover_cidrs":            "DiscoverCIDRs",
	// 会话表容量治理
	"session_max_count":       "SessionMaxCount",
	"session_idle_seconds":    "SessionIdleSeconds",
	"session_max_age_seconds": "SessionMaxAgeSeconds",
	// 可观测性
	"log_level":     "LogLevel",
	"log_format":    "LogFormat",
	"metrics_token": "MetricsToken",
	// 威胁情报（V1.5）
	"ti_enabled":           "TIEnabled",
	"ti_endpoint":          "TIEndpoint",
	"ti_api_key":           "TIAPIKey",
	"ti_timeout_ms":        "TITimeoutMS",
	"ti_cache_seconds":     "TICacheSeconds",
	"intel_push_token":     "IntelPushToken",
	"intel_retention_days": "IntelRetentionDays",
}

// 请求键里的别名（前端历史键名），不单独对应字段，不参与恢复校验。
// listFrom 的第一个参数才是正式键，别名不会出现在本表中。
var configKeyAliases = map[string]bool{
	"interfaces":                   true,
	"noise_min_bytes":              true,
	"noise_min_packets":            true,
	"reverse_proxy_host_threshold": true,
}

var (
	reFromCall = regexp.MustCompile(`(?:strFrom|numFrom|listFrom)\(\s*m\s*,\s*"([a-z_]+)"`)
	reMapIndex = regexp.MustCompile(`m\["([a-z_]+)"\]`)
	reSavedRef = regexp.MustCompile(`saved\.([A-Z][A-Za-z0-9]*)`)
)

// funcBody 取出源码中某个函数（或方法）的函数体文本。
// 用「下一个行首 func」当结束边界，够用且不依赖 AST —— 这里要的是"人写的清单"，
// 不是语义分析。
func funcBody(t *testing.T, src, signature string) string {
	t.Helper()
	start := strings.Index(src, signature)
	if start < 0 {
		t.Fatalf("源码里找不到 %q，签名变了就要同步改这个测试", signature)
	}
	rest := src[start+len(signature):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// TestPutConfigKeysRegistered 反向校验：putConfig 实际解析的每个键都必须在映射表里。
// 漏登记 = 新加的配置项没人提醒你去补恢复逻辑。
func TestPutConfigKeysRegistered(t *testing.T) {
	src := readRepoFile(t, "../../internal/api/server.go")
	body := funcBody(t, src, "func (s *Server) putConfig(")

	keys := map[string]bool{}
	for _, m := range reFromCall.FindAllStringSubmatch(body, -1) {
		keys[m[1]] = true
	}
	for _, m := range reMapIndex.FindAllStringSubmatch(body, -1) {
		keys[m[1]] = true
	}
	if len(keys) == 0 {
		t.Fatal("没有从 putConfig 中提取到任何配置键，正则可能已失效")
	}

	var missing []string
	for k := range keys {
		if configKeyAliases[k] {
			continue
		}
		if _, ok := configKeyToField[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("PUT /api/config 能改这些键，但没登记到 configKeyToField：%v\n"+
			"请同时确认它们已写进 mergeRuntimeConfig 的恢复逻辑", missing)
	}
}

// TestEveryWritableKeyIsRestored 正向校验：映射表里每个字段都必须在启动时被恢复。
func TestEveryWritableKeyIsRestored(t *testing.T) {
	src := readRepoFile(t, "main.go")
	body := funcBody(t, src, "func mergeRuntimeConfig(")

	restored := map[string]bool{}
	for _, m := range reSavedRef.FindAllStringSubmatch(body, -1) {
		restored[m[1]] = true
	}
	if len(restored) == 0 {
		t.Fatal("没有从 mergeRuntimeConfig 中提取到任何 saved.* 字段")
	}

	var missing []string
	for key, field := range configKeyToField {
		if !restored[field] {
			missing = append(missing, key+"→"+field)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("这些配置项能被 PUT /api/config 改，但重启后不会恢复：%v\n"+
			"（表现：后台改完一切正常，重启后静默回到默认值）", missing)
	}
}

// TestConfigKeyFieldsExist 映射表里的字段必须真实存在于 model.SystemConfig，
// 防止改字段名后映射表悄悄失效（那时前两个测试都会"通过"）。
func TestConfigKeyFieldsExist(t *testing.T) {
	typ := reflect.TypeOf(model.SystemConfig{})
	var bad []string
	for key, field := range configKeyToField {
		if _, ok := typ.FieldByName(field); !ok {
			bad = append(bad, key+"→"+field)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("configKeyToField 指向了不存在的字段：%v", bad)
	}
}

// TestNoDirectCfgFieldAccess 禁止再回到「裸指针直接读字段」的写法。
//
// 1.3.1 起配置收进 config.Box，读写都要经 Get/Update。
// 直接 s.d.Cfg.SomeField 会绕过锁，等于把刚修掉的数据竞争重新引回来，
// 但代码看上去完全正常——所以用测试兜住。
func TestNoDirectCfgFieldAccess(t *testing.T) {
	entries, err := os.ReadDir("../../internal/api")
	if err != nil {
		t.Fatalf("读取 internal/api 目录失败: %v", err)
	}
	reAnyUse := regexp.MustCompile(`s\.d\.Cfg(\.[A-Za-z_]+)?`)
	// 允许的形式：s.d.Cfg.Get() / .Update(...) / .Set(...) / 与 nil 比较
	allowed := map[string]bool{"Get": true, "Update": true, "Set": true}

	var bad []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src := readRepoFile(t, "../../internal/api/"+name)
		for _, m := range reAnyUse.FindAllString(src, -1) {
			if m == "s.d.Cfg" {
				continue
			}
			if allowed[strings.TrimPrefix(m, "s.d.Cfg.")] {
				continue
			}
			bad = append(bad, name+": "+m)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("发现绕过锁直接读配置：%v\n改为 s.cfg().字段（返回副本）", bad)
	}
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(b)
}
