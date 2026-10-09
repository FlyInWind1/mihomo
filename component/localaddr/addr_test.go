package localaddr

import (
	"net/netip"
	"testing"
)

func TestSetMergesSources(t *testing.T) {
	const tailscale = "tailscale"
	const other = "other"
	reset()
	t.Cleanup(reset)

	var got []netip.Prefix
	SetHandler(func(prefixes []netip.Prefix) {
		got = append([]netip.Prefix(nil), prefixes...)
	})

	Set(tailscale, []netip.Prefix{netip.MustParsePrefix("100.64.8.8/32")})
	Set(other, []netip.Prefix{netip.MustParsePrefix("10.147.20.8/32")})
	if len(got) != 2 || got[0].String() != "10.147.20.8/32" || got[1].String() != "100.64.8.8/32" {
		t.Fatalf("merged = %v", got)
	}

	Set(tailscale, nil)
	if len(got) != 1 || got[0].String() != "10.147.20.8/32" {
		t.Fatalf("after clearing tailscale = %v", got)
	}
}

func TestSetDropsInvalidAndDuplicates(t *testing.T) {
	reset()
	t.Cleanup(reset)

	var got []netip.Prefix
	SetHandler(func(prefixes []netip.Prefix) {
		got = append([]netip.Prefix(nil), prefixes...)
	})
	Set("tailscale", []netip.Prefix{
		netip.MustParsePrefix("100.64.8.8/32"),
		{},
		netip.PrefixFrom(netip.IPv4Unspecified(), 32),
	})
	Set("other", []netip.Prefix{netip.MustParsePrefix("100.64.8.8/32")})
	if len(got) != 1 || got[0].String() != "100.64.8.8/32" {
		t.Fatalf("merged = %v", got)
	}
}

func TestUnchangedSetDoesNotNotify(t *testing.T) {
	reset()
	t.Cleanup(reset)

	calls := 0
	SetHandler(func([]netip.Prefix) { calls++ })
	prefix := []netip.Prefix{netip.MustParsePrefix("100.64.8.8/32")}
	Set("tailscale", prefix)
	Set("tailscale", prefix)
	if calls != 2 {
		t.Fatalf("calls = %d, want the initial handler snapshot and one update", calls)
	}
	Notify()
	if calls != 3 {
		t.Fatalf("calls = %d, want a replay when the tun attaches", calls)
	}
}

func reset() {
	mu.Lock()
	sources = map[string][]netip.Prefix{}
	merged = nil
	handler = nil
	mu.Unlock()
}
