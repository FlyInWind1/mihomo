package outbound

import (
	"github.com/metacubex/mihomo/component/localaddr"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// EnsureTailscaleInbound starts every Tailscale node so peers can connect in
// without waiting for an outbound dial. start is idempotent, so a later call
// only brings up nodes added after the tun listener was already up.
// nodes is how many Tailscale nodes were found. failed is how many of those
// returned an error. nodes == 0 means the config has none.
func EnsureTailscaleInbound() (nodes, failed int) {
	forEachTailscale(func(node *Tailscale) {
		nodes++
		log.Infoln("[Tailscale](%s) starting for inbound", node.Name())
		if err := node.StartForInbound(); err != nil {
			failed++
			log.Warnln("[Tailscale](%s) start: %v", node.Name(), err)
		}
	})
	return nodes, failed
}

// LoadCachedTailscaleAddresses reads addresses saved from an earlier netmap.
// nodes is how many Tailscale proxies are configured. The CSV is empty when
// none of them has a saved address yet.
func LoadCachedTailscaleAddresses() (csv string, nodes int) {
	forEachTailscale(func(node *Tailscale) {
		nodes++
		prefixes := node.readCachedAddresses()
		if len(prefixes) == 0 {
			return
		}
		localaddr.Set(node.Name(), prefixes)
	})
	return localaddr.MergedCSV(), nodes
}

func forEachTailscale(fn func(*Tailscale)) {
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
			fn(node)
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
