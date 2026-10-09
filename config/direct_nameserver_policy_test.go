package config

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/orderedmap"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

func serveA(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(D.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(D.Msg)
			resp.SetReply(req)
			if req.Question[0].Qtype == D.TypeA {
				resp.Answer = append(resp.Answer, &D.A{
					Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1},
					A:   net.ParseIP(answer).To4(),
				})
			}
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(packed, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func nsPolicy(domain string, servers any) *orderedmap.OrderedMap[string, any] {
	policy := orderedmap.New[string, any]()
	policy.Set(domain, servers)
	return policy
}

func TestDirectNameserverPolicyQueriesDNSServer(t *testing.T) {
	private := serveA(t, "192.168.1.2")
	public := serveA(t, "203.0.113.10")

	newDirect := func(server string) *outbound.Direct {
		t.Helper()
		d, err := outbound.NewDirectWithOption(outbound.DirectOption{
			Name:             "DIRECT",
			NameServerPolicy: nsPolicy("nas.example.com", server),
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	resolve := func(d *outbound.Direct) netip.Addr {
		t.Helper()
		metadata := &C.Metadata{
			Host:    "nas.example.com",
			DstIP:   netip.MustParseAddr("198.51.100.1"),
			DstPort: 443,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := d.ResolveUDP(ctx, metadata); err != nil {
			t.Fatal(err)
		}
		return metadata.DstIP
	}

	if ip := resolve(newDirect(private)); ip != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("private dial ip = %s", ip)
	}
	if ip := resolve(newDirect(public)); ip != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("public dial ip = %s", ip)
	}
}

func TestDirectNameserverPolicyPureDropsHost(t *testing.T) {
	d, err := outbound.NewDirectWithOption(outbound.DirectOption{
		Name:             "DIRECT-Private",
		NameServerPolicy: nsPolicy("nas.example.com", "192.168.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{
		Host:    "nas.example.com",
		DstIP:   netip.MustParseAddr("203.0.113.10"),
		DNSMode: C.DNSMapping,
		DstPort: 443,
	}
	pure := metadata.Pure()
	if err := d.ResolveUDP(context.Background(), pure); err != nil {
		t.Fatal(err)
	}
	if pure.DstIP != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("udp ip = %s", pure.DstIP)
	}
}

func TestDirectNameserverPolicyMissKeepsAddress(t *testing.T) {
	d, err := outbound.NewDirectWithOption(outbound.DirectOption{
		Name:             "DIRECT-Private",
		NameServerPolicy: nsPolicy("nas.example.com", "192.168.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{
		Host:  "other.example.com",
		DstIP: netip.MustParseAddr("203.0.113.10"),
	}
	if err := d.ResolveUDP(context.Background(), metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.DstIP.String() != "203.0.113.10" {
		t.Fatalf("ip = %s", metadata.DstIP)
	}
}

func TestDirectNameserverPolicyAcceptsDNSServerSyntax(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
proxies:
  - name: DIRECT-Private
    type: direct
    nameserver-policy:
      "+.lan": 192.168.1.2
      nas.example.com:
        - tls://192.168.1.2:853
        - https://doh.pub/dns-query
`))
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := raw.Proxy[0]["nameserver-policy"].(*orderedmap.OrderedMap[string, any])
	if !ok || policy.Len() != 2 {
		t.Fatalf("nameserver-policy = %#v", raw.Proxy[0]["nameserver-policy"])
	}
	if pair := policy.Oldest(); pair == nil || pair.Key != "+.lan" || pair.Next() == nil || pair.Next().Key != "nas.example.com" {
		t.Fatalf("nameserver-policy order = %#v", policy)
	}
	if _, err := adapter.ParseProxy(raw.Proxy[0]); err != nil {
		t.Fatal(err)
	}

	_, err = outbound.NewDirectWithOption(outbound.DirectOption{
		Name:             "DIRECT-Private",
		NameServerPolicy: nsPolicy("nas.example.com", "foo://192.168.1.2"),
	})
	if err == nil {
		t.Fatal("expected unsupported DNS scheme to be rejected")
	}
}
