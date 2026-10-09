//go:build with_gvisor && !no_tailscale

package outbound

import (
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
