// Package probe 主动端口扫描：调用系统 nmap（不自己造轮子），解析 XML 输出。
package probe

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"starmap/internal/model"
)

// nmap -oX 输出结构（精简：只取 host/address/ports/port）。
type nmapXML struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}
type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}
type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}
type nmapService struct {
	Name string `xml:"name,attr"`
}

// NmapPathOf 归一化 nmap 路径（空则用默认 "nmap"）。
func NmapPathOf(path string) string {
	if path == "" {
		return "nmap"
	}
	return path
}

// NmapAvailable 检测 nmap 是否可用。
func NmapAvailable(nmapPath string) bool {
	_, err := exec.LookPath(NmapPathOf(nmapPath))
	return err == nil
}

// RunNmapScan 执行 nmap 端口扫描，解析出开放端口记录。
// target：单 IP 或 CIDR；ports：nmap -p 参数（如 "1-65535" 全端口）；rate：-T 模板（T0~T5）。
func RunNmapScan(nmapPath, target, ports, rate string) ([]model.PortRecord, error) {
	p := NmapPathOf(nmapPath)
	if ports == "" {
		ports = "1-65535" // 默认全端口
	}
	if rate == "" {
		rate = "T4"
	}
	args := []string{"-sT", "-p", ports, "-" + rate, "--min-rate", "2000", "-oX", "-", target}
	out, err := exec.Command(p, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap 执行失败: %v（输出：%s）", err, firstN(string(out), 400))
	}
	records := parseNmapXML(out)
	if records == nil {
		return nil, fmt.Errorf("nmap 输出解析失败（目标可能无存活主机或输出异常）")
	}
	return records, nil
}

// parseNmapXML 解析 nmap -oX 输出，返回 open 端口记录（Source=probe）。
func parseNmapXML(data []byte) []model.PortRecord {
	var doc nmapXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	now := time.Now()
	var out []model.PortRecord
	for _, h := range doc.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "" {
				ip = a.Addr
			}
		}
		if ip == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			proto := strings.ToLower(p.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			out = append(out, model.PortRecord{
				IP:        ip,
				Port:      p.PortID,
				Proto:     proto,
				Service:   p.Service.Name,
				State:     "open",
				Source:    model.PortSourceProbe,
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}
	return out
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
