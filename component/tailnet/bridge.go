package tailnet

import (
	"io"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/localaddr"
)

const inboundQueue = 256

// Bridge tracks one Tailscale node's addresses.
// Packets tsnet writes for the host are sent to the current kernel tun.
// Replies to those packets are queued for tsnet. Other host traffic is not.
// name is the proxy name used as the key when reporting this node's prefixes.
type Bridge struct {
	name    string
	addrs   atomic.Pointer[addrSet]
	inbound chan []byte
	done    chan struct{}
	once    sync.Once
}

type addrSet struct {
	addrs []netip.Addr
}

type bridgeTable struct {
	bridges []*Bridge
}

type kernelSink struct {
	w io.Writer
}

var (
	bridges atomic.Pointer[bridgeTable]
	kernel  atomic.Pointer[kernelSink]

	publishMu sync.Mutex
	handler   func([]netip.Prefix)
	last      []netip.Prefix
)

func NewBridge(name string) *Bridge {
	b := &Bridge{
		name:    name,
		inbound: make(chan []byte, inboundQueue),
		done:    make(chan struct{}),
	}
	register(b)
	return b
}

func (b *Bridge) SetAddresses(addrs []netip.Addr) {
	next := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IsValid() && !addr.IsUnspecified() {
			next = append(next, addr)
		}
	}
	if b.same(next) {
		return
	}
	b.addrs.Store(&addrSet{addrs: next})
	publishAddresses(false)
	localaddr.Set(b.name, b.prefixes())
}

func (b *Bridge) same(addrs []netip.Addr) bool {
	set := b.addrs.Load()
	if set == nil {
		return len(addrs) == 0
	}
	if len(set.addrs) != len(addrs) {
		return false
	}
	for i := range set.addrs {
		if set.addrs[i] != addrs[i] {
			return false
		}
	}
	return true
}

func (b *Bridge) owns(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	set := b.addrs.Load()
	if set == nil {
		return false
	}
	for _, candidate := range set.addrs {
		if candidate == addr {
			return true
		}
	}
	return false
}

// Read blocks until a reply to a packet this node wrote to the host is
// queued, or the bridge closes.
func (b *Bridge) Read() ([]byte, error) {
	select {
	case packet := <-b.inbound:
		return packet, nil
	case <-b.done:
		return nil, io.EOF
	}
}

func (b *Bridge) deliver(packet []byte) {
	select {
	case <-b.done:
		return
	default:
	}
	cloned := append([]byte(nil), packet...)
	ClampTCPMSS(cloned)
	select {
	case <-b.done:
	case b.inbound <- cloned:
	default:
	}
}

func (b *Bridge) Close() {
	b.once.Do(func() {
		dropReplies(b)
		unregister(b)
		close(b.done)
		b.addrs.Store(&addrSet{})
		publishAddresses(false)
		localaddr.Set(b.name, nil)
	})
}

// AttachKernel selects the tun device that receives packets for the host.
// The previous device, if it is still current, must be detached by its owner.
func AttachKernel(w io.Writer) {
	kernel.Store(&kernelSink{w: w})
	publishAddresses(true)
	localaddr.Notify()
}

// DetachKernel clears the kernel tun when it is still the current one.
func DetachKernel(w io.Writer) {
	current := kernel.Load()
	if current != nil && current.w == w {
		kernel.CompareAndSwap(current, nil)
	}
}

// WriteKernel delivers one packet toward the host. It copies packet before
// clamping MSS, so the caller may reuse its buffer.
func WriteKernel(packet []byte) error {
	sink := kernel.Load()
	if sink == nil || sink.w == nil || len(packet) == 0 {
		return nil
	}
	out := append([]byte(nil), packet...)
	ClampTCPMSS(out)
	_, err := sink.w.Write(out)
	if err == nil {
		noteInjected(out)
	}
	return err
}

// SetAddressHandler receives the node's tailnet prefixes whenever they change,
// and once immediately with the current set.
func SetAddressHandler(fn func([]netip.Prefix)) {
	publishMu.Lock()
	handler = fn
	prefixes := append([]netip.Prefix(nil), last...)
	publishMu.Unlock()
	if fn != nil {
		fn(prefixes)
	}
}

func register(bridge *Bridge) {
	for {
		old := bridges.Load()
		next := &bridgeTable{}
		if old != nil {
			next.bridges = append(append([]*Bridge{}, old.bridges...), bridge)
		} else {
			next.bridges = []*Bridge{bridge}
		}
		if bridges.CompareAndSwap(old, next) {
			return
		}
	}
}

func unregister(bridge *Bridge) {
	for {
		old := bridges.Load()
		if old == nil {
			return
		}
		next := &bridgeTable{}
		for _, candidate := range old.bridges {
			if candidate != bridge {
				next.bridges = append(next.bridges, candidate)
			}
		}
		if bridges.CompareAndSwap(old, next) {
			return
		}
	}
}

func publishAddresses(force bool) {
	prefixes := collectPrefixes()
	publishMu.Lock()
	changed := !samePrefixes(last, prefixes)
	if changed {
		last = prefixes
	}
	fn := handler
	snapshot := append([]netip.Prefix(nil), prefixes...)
	publishMu.Unlock()
	if fn != nil && (changed || force) {
		fn(snapshot)
	}
}

func (b *Bridge) prefixes() []netip.Prefix {
	set := b.addrs.Load()
	if set == nil || len(set.addrs) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(set.addrs))
	for _, addr := range set.addrs {
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out
}

func collectPrefixes() []netip.Prefix {
	table := bridges.Load()
	if table == nil {
		return nil
	}
	var prefixes []netip.Prefix
	for _, bridge := range table.bridges {
		set := bridge.addrs.Load()
		if set == nil {
			continue
		}
		for _, addr := range set.addrs {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	if len(prefixes) == 0 {
		return nil
	}
	out := prefixes[:1]
	for _, prefix := range prefixes[1:] {
		if prefix != out[len(out)-1] {
			out = append(out, prefix)
		}
	}
	return out
}

func samePrefixes(a, b []netip.Prefix) bool {
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
