package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// settings 探针的可持久化配置。
//
// 为什么要有配置文件：命令行参数适合临时排查，不适合部署。写进 systemd 单元
// 或 Windows 服务的 binPath 时，十几个 flag 拼在一行里既没法审阅也没法 diff，
// 改一个值要重建服务。企业内网里"改配置"和"重装服务"是两件完全不同量级的事。
//
// 优先级：内置默认值 < 配置文件 < 命令行显式指定的参数。
// 这样配置文件可以长期存在，临时排查时用 flag 覆盖即可。
type settings struct {
	Server   string `yaml:"server"`
	Token    string `yaml:"token"`
	ProbeID  string `yaml:"probe_id"`
	Name     string `yaml:"name"`
	Location string `yaml:"location"`

	Source string `yaml:"source"`
	Iface  string `yaml:"iface"`

	// 时长用字符串写（"10s"、"1m"），比让人算纳秒友好。
	Interval string `yaml:"interval"`
	Report   string `yaml:"report"`

	Batch    int   `yaml:"batch"`
	Buffer   int   `yaml:"buffer"`
	LongConn int64 `yaml:"long_conn_seconds"`
	// HeartbeatBytes 心跳包字节阈值，对应服务端 heartbeat_max_bytes。
	HeartbeatBytes int `yaml:"heartbeat_max_bytes"`

	Once   bool `yaml:"once"`
	DryRun bool `yaml:"dry_run"`
}

func defaultSettings() settings {
	return settings{
		Server:         "http://127.0.0.1:8080",
		Source:         "auto",
		Interval:       "10s",
		Report:         "60s",
		Batch:          500,
		Buffer:         20000,
		LongConn:       3600,
		HeartbeatBytes: 64,
	}
}

// loadSettings 读 YAML 覆盖到 s 上。文件里的零值不覆盖（省略即"用默认"），
// 这样配置文件可以只写关心的几项。
func loadSettings(path string, s *settings) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	var f settings
	if err := yaml.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("解析配置文件失败（检查缩进与引号）: %w", err)
	}
	if f.Server != "" {
		s.Server = f.Server
	}
	if f.Token != "" {
		s.Token = f.Token
	}
	if f.ProbeID != "" {
		s.ProbeID = f.ProbeID
	}
	if f.Name != "" {
		s.Name = f.Name
	}
	if f.Location != "" {
		s.Location = f.Location
	}
	if f.Source != "" {
		s.Source = f.Source
	}
	if f.Iface != "" {
		s.Iface = f.Iface
	}
	if f.Interval != "" {
		s.Interval = f.Interval
	}
	if f.Report != "" {
		s.Report = f.Report
	}
	if f.Batch > 0 {
		s.Batch = f.Batch
	}
	if f.Buffer > 0 {
		s.Buffer = f.Buffer
	}
	if f.LongConn > 0 {
		s.LongConn = f.LongConn
	}
	if f.HeartbeatBytes > 0 {
		s.HeartbeatBytes = f.HeartbeatBytes
	}
	s.Once = s.Once || f.Once
	s.DryRun = s.DryRun || f.DryRun
	return nil
}

// durations 解析两个时长字段并给出可读的失败信息。
// 直接让 time.ParseDuration 报 "time: invalid duration" 的话，
// 用户还得自己回去找是哪一行写错了。
func (s *settings) durations() (interval, report time.Duration, err error) {
	if interval, err = time.ParseDuration(s.Interval); err != nil {
		return 0, 0, fmt.Errorf("interval %q 不是合法时长（示例：10s、1m）: %w", s.Interval, err)
	}
	if report, err = time.ParseDuration(s.Report); err != nil {
		return 0, 0, fmt.Errorf("report %q 不是合法时长（示例：60s、2m）: %w", s.Report, err)
	}
	if interval <= 0 {
		return 0, 0, fmt.Errorf("interval 必须大于 0")
	}
	if report <= 0 {
		return 0, 0, fmt.Errorf("report 必须大于 0")
	}
	return interval, report, nil
}
