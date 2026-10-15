package probe

import (
	"testing"

	"starmap/internal/model"
)

func TestParseNmapXML(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.31.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/><service name="http-alt"/></port>
    </ports>
  </host>
  <host>
    <address addr="192.168.31.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
    </ports>
  </host>
</nmaprun>`
	records := parseNmapXML([]byte(xml))
	if len(records) != 4 {
		t.Fatalf("应解析 4 个 open 端口（忽略 closed），实际 %d", len(records))
	}
	// 第一个：22/tcp ssh
	if records[0].IP != "192.168.31.1" || records[0].Port != 22 || records[0].Proto != "tcp" || records[0].Service != "ssh" {
		t.Fatalf("首条端口解析错误: %+v", records[0])
	}
	if records[0].Source != model.PortSourceProbe || records[0].State != "open" {
		t.Fatalf("来源/状态错误: %+v", records[0])
	}
	// udp 53
	found := false
	for _, r := range records {
		if r.IP == "192.168.31.2" && r.Port == 53 && r.Proto == "udp" && r.Service == "domain" {
			found = true
		}
	}
	if !found {
		t.Fatal("应解析出 udp/53 domain")
	}
}

func TestParseNmapXMLBadInput(t *testing.T) {
	if parseNmapXML([]byte("not xml")) != nil {
		t.Fatal("非法 XML 应返回 nil")
	}
}
