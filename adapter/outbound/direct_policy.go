package outbound

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/metacubex/mihomo/common/orderedmap"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/randv2"
)

func buildDirectNameserverPolicy(proxyName string, raw *orderedmap.OrderedMap[string, any]) (*dns.Resolver, error) {
	if raw == nil || raw.Len() == 0 {
		return nil, nil
	}
	if dns.ParseNameServerPolicy == nil {
		return nil, fmt.Errorf("direct %s nameserver-policy: parser is not initialized", proxyName)
	}
	policies, err := dns.ParseNameServerPolicy(raw, fmt.Sprintf("proxies[%s].nameserver-policy", proxyName))
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, nil
	}
	return dns.NewResolver(dns.Config{
		Policy: policies,
		IPv6:   true,
	}).Resolver, nil
}

func policyHost(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}
	return metadata.Host
}

func (d *Direct) resolveNameserverPolicy(ctx context.Context, host string) (netip.Addr, bool, error) {
	if d.nameserverPolicy == nil || host == "" || !d.nameserverPolicy.PolicyMatched(host) {
		return netip.Addr{}, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = resolver.WithInitiator(ctx, resolver.InitiatorDirect)
	if node, ok := resolver.DefaultHosts.Search(host, false); ok {
		ip, err := node.RandIP()
		if err != nil {
			return netip.Addr{}, true, err
		}
		return ip, true, nil
	}
	var (
		ips []netip.Addr
		err error
	)
	switch d.prefer {
	case C.IPv4Only:
		ips, err = d.nameserverPolicy.LookupIPv4(ctx, host)
	case C.IPv6Only:
		ips, err = d.nameserverPolicy.LookupIPv6(ctx, host)
	default:
		ips, err = d.nameserverPolicy.LookupIP(ctx, host)
	}
	if err != nil {
		return netip.Addr{}, true, fmt.Errorf("direct %s nameserver-policy resolve %s: %w", d.name, host, err)
	}
	ip, err := pickPolicyAnswer(ips, d.prefer)
	if err != nil {
		return netip.Addr{}, true, fmt.Errorf("direct %s nameserver-policy resolve %s: %w", d.name, host, err)
	}
	log.Debugln("[Direct] %s nameserver-policy %s --> %s", d.name, host, ip)
	return ip, true, nil
}

func pickPolicyAnswer(ips []netip.Addr, prefer C.DNSPrefer) (netip.Addr, error) {
	v4, v6 := resolver.SortationAddr(ips)
	var chosen []netip.Addr
	switch prefer {
	case C.IPv4Only:
		chosen = v4
	case C.IPv6Only:
		chosen = v6
	case C.IPv6Prefer:
		if len(v6) > 0 {
			chosen = v6
		} else {
			chosen = v4
		}
	default:
		if len(v4) > 0 {
			chosen = v4
		} else {
			chosen = v6
		}
	}
	if len(chosen) == 0 {
		return netip.Addr{}, fmt.Errorf("%w", resolver.ErrIPNotFound)
	}
	return chosen[randv2.IntN(len(chosen))], nil
}

func (d *Direct) metadataForNameserverPolicy(ctx context.Context, metadata *C.Metadata) (*C.Metadata, error) {
	ip, matched, err := d.resolveNameserverPolicy(ctx, policyHost(metadata))
	if err != nil || !matched {
		return metadata, err
	}
	cloned := metadata.Clone()
	cloned.Host = ""
	cloned.DstIP = ip
	return cloned, nil
}

func (d *Direct) applyNameserverPolicy(ctx context.Context, metadata *C.Metadata) (bool, error) {
	ip, matched, err := d.resolveNameserverPolicy(ctx, policyHost(metadata))
	if err != nil || !matched {
		return false, err
	}
	metadata.DstIP = ip
	return true, nil
}
