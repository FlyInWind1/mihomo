package tailnet

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/localaddr"
)

func TestReplyToInjectedFlowReturnsToBridge(t *testing.T) {
	bridge := NewBridge("node")
	defer bridge.Close()
	node := netip.MustParseAddr("100.111.1.24")
	peer := netip.MustParseAddr("100.111.1.5")
	bridge.SetAddresses([]netip.Addr{node})

	writer := &memWriter{}
	AttachKernel(writer)
	defer DetachKernel(writer)

	syn := ipv4TCP(peer, node, 43210, 8022, true, 1200)
	if err := WriteKernel(syn); err != nil {
		t.Fatal(err)
	}
	reply := ipv4TCP(node, peer, 8022, 43210, false, 1460)
	if !TakeReply(reply) {
		t.Fatal("reply to the injected flow was not returned")
	}
	if _, err := bridge.Read(); err != nil {
		t.Fatal(err)
	}

	public := ipv4TCP(node, netip.MustParseAddr("1.1.1.1"), 40000, 443, false, 1460)
	if TakeReply(public) {
		t.Fatal("public traffic sourced from the node address was taken")
	}
	fresh := ipv4TCP(node, netip.MustParseAddr("100.111.1.9"), 40000, 22, true, 1200)
	if TakeReply(fresh) {
		t.Fatal("a new tailnet connection was taken")
	}
}

func TestWriteKernelClampsMSS(t *testing.T) {
	writer := &memWriter{}
	AttachKernel(writer)
	defer DetachKernel(writer)

	packet := ipv4TCP(netip.MustParseAddr("100.64.8.9"), netip.MustParseAddr("100.64.8.8"), 50000, 22, true, 8000)
	if err := WriteKernel(packet); err != nil {
		t.Fatal(err)
	}
	if mssOf(t, writer.b) != mssIPv4 {
		t.Fatalf("MSS = %d, want %d", mssOf(t, writer.b), mssIPv4)
	}
	if !validTCPChecksum(t, writer.b) {
		t.Fatal("TCP checksum is not valid after MSS clamp")
	}
	if mssOf(t, packet) != 8000 {
		t.Fatal("WriteKernel modified the caller's packet")
	}
}

func TestClampIPv6MSS(t *testing.T) {
	packet := ipv6TCP(netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("fd7a:115c:a1e0::2"), 50000, 22, true, 8000)
	ClampTCPMSS(packet)
	if mssOf(t, packet) != mssIPv6 {
		t.Fatalf("MSS = %d, want %d", mssOf(t, packet), mssIPv6)
	}
	if !validTCPChecksum(t, packet) {
		t.Fatal("IPv6 TCP checksum is not valid after MSS clamp")
	}
}

func TestAddressHandlerSeesNodePrefix(t *testing.T) {
	bridge := NewBridge("node")
	defer bridge.Close()

	var got []netip.Prefix
	SetAddressHandler(func(prefixes []netip.Prefix) {
		got = append([]netip.Prefix(nil), prefixes...)
	})
	defer SetAddressHandler(nil)

	bridge.SetAddresses([]netip.Addr{netip.MustParseAddr("100.64.8.8")})
	if len(got) != 1 || got[0] != netip.MustParsePrefix("100.64.8.8/32") {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestBridgeReportsEachProxyName(t *testing.T) {
	home := NewBridge("home")
	defer home.Close()
	office := NewBridge("office")
	defer office.Close()

	var got []netip.Prefix
	localaddr.SetHandler(func(prefixes []netip.Prefix) {
		got = append([]netip.Prefix(nil), prefixes...)
	})
	t.Cleanup(func() { localaddr.SetHandler(nil) })

	home.SetAddresses([]netip.Addr{netip.MustParseAddr("100.64.8.8")})
	office.SetAddresses([]netip.Addr{netip.MustParseAddr("10.147.20.8")})
	if len(got) != 2 || got[0].String() != "10.147.20.8/32" || got[1].String() != "100.64.8.8/32" {
		t.Fatalf("merged = %v", got)
	}

	office.Close()
	if len(got) != 1 || got[0].String() != "100.64.8.8/32" {
		t.Fatalf("after office closed = %v", got)
	}
}

type memWriter struct {
	b []byte
}

func (w *memWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func ipv4TCP(src, dst netip.Addr, sport, dport int, syn bool, mss int) []byte {
	packet := make([]byte, 44)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 44
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	putTCP(packet[20:], sport, dport, syn, mss)
	ipSum := internetChecksum(packet[:20])
	packet[10] = byte(ipSum >> 8)
	packet[11] = byte(ipSum)
	sum := tcpChecksum(src, dst, packet[20:])
	packet[36] = byte(sum >> 8)
	packet[37] = byte(sum)
	return packet
}

func ipv6TCP(src, dst netip.Addr, sport, dport int, syn bool, mss int) []byte {
	packet := make([]byte, 64)
	packet[0] = 0x60
	packet[4] = 0
	packet[5] = 24
	packet[6] = 6
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())
	putTCP(packet[40:], sport, dport, syn, mss)
	sum := tcpChecksum(src, dst, packet[40:])
	packet[56] = byte(sum >> 8)
	packet[57] = byte(sum)
	return packet
}

func putTCP(tcp []byte, sport, dport int, syn bool, mss int) {
	tcp[0] = byte(sport >> 8)
	tcp[1] = byte(sport)
	tcp[2] = byte(dport >> 8)
	tcp[3] = byte(dport)
	tcp[12] = 6 << 4
	if syn {
		tcp[13] = 0x02
	} else {
		tcp[13] = 0x10
	}
	tcp[20] = 2
	tcp[21] = 4
	tcp[22] = byte(mss >> 8)
	tcp[23] = byte(mss)
}

func mssOf(t *testing.T, packet []byte) int {
	t.Helper()
	tcp, _, ok := tcpHeader(packet)
	if !ok {
		t.Fatal("not a TCP packet")
	}
	headerLen := int(tcp[12]>>4) * 4
	opts := tcp[20:headerLen]
	for i := 0; i+1 < len(opts); {
		if opts[i] == 1 {
			i++
			continue
		}
		if opts[i] == 0 {
			break
		}
		optLen := int(opts[i+1])
		if opts[i] == 2 && optLen == 4 {
			return int(opts[i+2])<<8 | int(opts[i+3])
		}
		if optLen < 2 {
			break
		}
		i += optLen
	}
	t.Fatal("MSS option missing")
	return 0
}

func validTCPChecksum(t *testing.T, packet []byte) bool {
	t.Helper()
	tcp, _, ok := tcpHeader(packet)
	if !ok {
		t.Fatal("not a TCP packet")
	}
	src, dst, ok := testPacketAddrs(packet)
	if !ok {
		t.Fatal("addresses missing")
	}
	got := uint16(tcp[16])<<8 | uint16(tcp[17])
	want := tcpChecksum(src, dst, tcp)
	return got == want
}

func testPacketAddrs(packet []byte) (src, dst netip.Addr, ok bool) {
	if len(packet) < 1 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func tcpChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	header := append([]byte(nil), tcp...)
	header[16] = 0
	header[17] = 0
	sum := checksumAdd(0, src.AsSlice())
	sum = checksumAdd(sum, dst.AsSlice())
	proto := []byte{0, 0, 0, 6}
	if dst.Is4() {
		proto = []byte{0, 6}
	}
	sum = checksumAdd(sum, proto)
	length := []byte{byte(len(tcp) >> 8), byte(len(tcp))}
	sum = checksumAdd(sum, length)
	sum = checksumAdd(sum, header)
	sum = ^sum
	if sum == 0 {
		sum = 0xffff
	}
	return sum
}

func internetChecksum(b []byte) uint16 {
	return ^checksumAdd(0, b)
}

func checksumAdd(sum uint16, b []byte) uint16 {
	acc := uint32(sum)
	for len(b) >= 2 {
		acc += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	for acc > 0xffff {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return uint16(acc)
}
