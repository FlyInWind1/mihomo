package localaddr

import (
	"net/netip"
	"sort"
	"sync"
)

// Prefixes the Android VPN must treat as local. Each proxy reports its own
// set under its name; the merged list is what VpnService passes to addAddress.
// Tailscale packet diversion keeps a separate set and does not read this one.
var (
	mu      sync.Mutex
	sources = map[string][]netip.Prefix{}
	merged  []netip.Prefix
	handler func([]netip.Prefix)
)

// Set replaces the prefixes owned by one proxy. source is that proxy's name.
// The handler runs when the merged set changes.
func Set(source string, prefixes []netip.Prefix) {
	if source == "" {
		return
	}
	next := normalize(prefixes)
	mu.Lock()
	previous, exists := sources[source]
	unchanged := (exists && same(previous, next)) || (!exists && len(next) == 0)
	if unchanged {
		mu.Unlock()
		return
	}
	if len(next) == 0 {
		delete(sources, source)
	} else {
		sources[source] = next
	}
	merged = collectLocked()
	fn := handler
	snapshot := append([]netip.Prefix(nil), merged...)
	mu.Unlock()
	if fn != nil {
		fn(snapshot)
	}
}

// Notify delivers the current merged set even when no proxy changed, so a tun
// that attaches later still receives addresses learned beforehand.
func Notify() {
	mu.Lock()
	fn := handler
	snapshot := append([]netip.Prefix(nil), merged...)
	mu.Unlock()
	if fn != nil {
		fn(snapshot)
	}
}

// SetHandler receives the merged prefixes whenever they change, and once
// immediately with the current set.
func SetHandler(fn func([]netip.Prefix)) {
	mu.Lock()
	handler = fn
	snapshot := append([]netip.Prefix(nil), merged...)
	mu.Unlock()
	if fn != nil {
		fn(snapshot)
	}
}

func normalize(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() {
			continue
		}
		out = append(out, prefix.Masked())
	}
	return dedupe(out)
}

func collectLocked() []netip.Prefix {
	if len(sources) == 0 {
		return nil
	}
	var all []netip.Prefix
	for _, prefixes := range sources {
		all = append(all, prefixes...)
	}
	return dedupe(all)
}

func dedupe(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].Addr().Less(prefixes[j].Addr()) ||
			(prefixes[i].Addr() == prefixes[j].Addr() && prefixes[i].Bits() < prefixes[j].Bits())
	})
	out := prefixes[:1]
	for _, prefix := range prefixes[1:] {
		if prefix != out[len(out)-1] {
			out = append(out, prefix)
		}
	}
	return out
}

func same(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
