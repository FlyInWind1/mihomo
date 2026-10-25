//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net/netip"
	"runtime"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestUnwrapProxyAdapterReachesTailscale(t *testing.T) {
	node := &Tailscale{Base: NewBase(BaseOption{Name: "ts", Type: C.Tailscale})}
	wrapped := NewAutoCloseProxyAdapter(&SingMux{ProxyAdapter: node})
	runtime.SetFinalizer(wrapped, nil)

	if got := unwrapProxyAdapter(wrapped); got != node {
		t.Fatalf("unwrap = %T, want the Tailscale node under autoClose and sing-mux", got)
	}
}

func TestCachedAddressesRoundTrip(t *testing.T) {
	node := &Tailscale{option: TailscaleOption{StateDir: t.TempDir()}}
	node.writeCachedAddresses([]netip.Addr{netip.MustParseAddr("100.111.1.24")})
	got := node.readCachedAddresses()
	if len(got) != 1 || got[0].String() != "100.111.1.24/32" {
		t.Fatalf("cached = %v", got)
	}
}
