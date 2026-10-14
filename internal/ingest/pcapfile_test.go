package ingest

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// genTestPCAP 程序生成一个小 PCAP：2 个 TCP 包 + 1 个 UDP 包。
func genTestPCAP(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	writePkt := func(proto layers.IPProtocol, sp, dp uint16, payload []byte) {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64, Protocol: proto,
			SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{93, 184, 216, 34},
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if proto == layers.IPProtocolTCP {
			tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: 1, Window: 65535}
			tcp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
				t.Fatal(err)
			}
		} else {
			udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
			udp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
				t.Fatal(err)
			}
		}
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}

	writePkt(layers.IPProtocolTCP, 5000, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	writePkt(layers.IPProtocolTCP, 80, 5000, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	writePkt(layers.IPProtocolUDP, 12345, 53, []byte("dns-query"))
}

func TestOpenPCAPFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	genTestPCAP(t, path)

	src, err := OpenPCAPFile(path)
	if err != nil {
		t.Fatalf("OpenPCAPFile: %v", err)
	}
	var count, tcp, udp int
	for info := range src {
		count++
		if info.SrcIP == "" || info.DstIP == "" {
			t.Fatal("IP 未解析")
		}
		switch info.Proto {
		case "tcp":
			tcp++
		case "udp":
			udp++
		}
		if info.TTL != 64 {
			t.Fatalf("TTL = %d", info.TTL)
		}
		if info.SrcMAC == "" {
			t.Fatal("MAC 未解析")
		}
	}
	if count != 3 || tcp != 2 || udp != 1 {
		t.Fatalf("count=%d tcp=%d udp=%d, want 3/2/1", count, tcp, udp)
	}
}

func TestOpenPCAPFileBadMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	os.WriteFile(path, []byte("not a pcap file at all"), 0o644)
	if _, err := OpenPCAPFile(path); err == nil {
		t.Fatal("坏文件应报错")
	}
}
