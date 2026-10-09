package outbound

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// EnsureTailscaleInbound starts every Tailscale node so peers can connect in
// without waiting for an outbound dial. start is idempotent, so a later call
// only brings up nodes added after the tun listener was already up.
func EnsureTailscaleInbound() {
	seen := map[C.ProxyAdapter]struct{}{}
	var walk func(adapter C.ProxyAdapter)
	walk = func(adapter C.ProxyAdapter) {
		if adapter == nil {
			return
		}
		if _, ok := seen[adapter]; ok {
			return
		}
		seen[adapter] = struct{}{}
		// ParseProxy wraps the outbound in autoClose, and sometimes sing-mux,
		// so the value stored on the tunnel is not *Tailscale itself.
		adapter = unwrapProxyAdapter(adapter)
		if adapter == nil {
			return
		}
		if _, ok := seen[adapter]; ok {
			return
		}
		seen[adapter] = struct{}{}
		if node, ok := adapter.(*Tailscale); ok {
			log.Infoln("[Tailscale](%s) starting for inbound", node.Name())
			if err := node.StartForInbound(); err != nil {
				log.Warnln("[Tailscale](%s) start: %v", node.Name(), err)
			}
			return
		}
		group, ok := adapter.(interface{ Proxies() []C.Proxy })
		if !ok {
			return
		}
		for _, proxy := range group.Proxies() {
			walk(proxy.Adapter())
		}
	}
	for _, proxy := range tunnel.Proxies() {
		walk(proxy.Adapter())
	}
	for _, provider := range tunnel.Providers() {
		for _, proxy := range provider.Proxies() {
			walk(proxy.Adapter())
		}
	}
}

// unwrapProxyAdapter peels the wrappers ParseProxy puts around an outbound.
func unwrapProxyAdapter(adapter C.ProxyAdapter) C.ProxyAdapter {
	for adapter != nil {
		switch wrapped := adapter.(type) {
		case *autoCloseProxyAdapter:
			adapter = wrapped.ProxyAdapter
		case *SingMux:
			adapter = wrapped.ProxyAdapter
		default:
			return adapter
		}
	}
	return nil
}
