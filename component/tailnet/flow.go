package tailnet

import (
	"net/netip"
	"sync"
	"time"
)

const replyIdle = 24 * time.Hour

// flowKey is one direction of a TCP or UDP flow.
type flowKey struct {
	proto uint8
	src   netip.Addr
	dst   netip.Addr
	sport uint16
	dport uint16
}

type replyEntry struct {
	bridge *Bridge
	seen   time.Time
}

type replyTable struct {
	mu    sync.Mutex
	flows map[flowKey]replyEntry
}

var replies = replyTable{flows: map[flowKey]replyEntry{}}

// noteInjected records the reply direction of a packet just written to the
// host, when that packet was addressed to this node's own Tailscale address.
func noteInjected(packet []byte) {
	src, dst, proto, sport, dport, ok := packetTuple(packet)
	if !ok {
		return
	}
	bridge := bridgeByAddr(dst)
	if bridge == nil {
		return
	}
	replies.note(flowKey{proto: proto, src: dst, dst: src, sport: dport, dport: sport}, bridge)
}

// TakeReply reports whether packet is the host's reply to a packet this node
// already wrote to the host. A match is queued for that node.
func TakeReply(packet []byte) bool {
	src, dst, proto, sport, dport, ok := packetTuple(packet)
	if !ok {
		return false
	}
	bridge := replies.match(flowKey{proto: proto, src: src, dst: dst, sport: sport, dport: dport}, tcpClosing(packet))
	if bridge == nil {
		return false
	}
	bridge.deliver(packet)
	return true
}

func (t *replyTable) note(key flowKey, bridge *Bridge) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked()
	t.flows[key] = replyEntry{bridge: bridge, seen: time.Now()}
}

func (t *replyTable) match(key flowKey, closing bool) *Bridge {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked()
	entry, ok := t.flows[key]
	if !ok {
		return nil
	}
	if closing {
		delete(t.flows, key)
	} else {
		entry.seen = time.Now()
		t.flows[key] = entry
	}
	return entry.bridge
}

func dropReplies(bridge *Bridge) {
	replies.mu.Lock()
	defer replies.mu.Unlock()
	for key, entry := range replies.flows {
		if entry.bridge == bridge {
			delete(replies.flows, key)
		}
	}
}

func (t *replyTable) sweepLocked() {
	now := time.Now()
	for key, entry := range t.flows {
		if now.Sub(entry.seen) > replyIdle {
			delete(t.flows, key)
		}
	}
}

func bridgeByAddr(addr netip.Addr) *Bridge {
	table := bridges.Load()
	if table == nil {
		return nil
	}
	for _, bridge := range table.bridges {
		if bridge.owns(addr) {
			return bridge
		}
	}
	return nil
}

func packetTuple(packet []byte) (src, dst netip.Addr, proto uint8, sport, dport uint16, ok bool) {
	if len(packet) < 1 {
		return
	}
	var headerLen int
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return
		}
		headerLen = int(packet[0]&0x0f) * 4
		if headerLen < 20 || len(packet) < headerLen {
			return
		}
		frag := int(packet[6]&0x1f)<<8 | int(packet[7])
		if frag != 0 {
			return
		}
		proto = packet[9]
		src = netip.AddrFrom4([4]byte(packet[12:16]))
		dst = netip.AddrFrom4([4]byte(packet[16:20]))
	case 6:
		if len(packet) < 40 {
			return
		}
		headerLen = 40
		proto = packet[6]
		src = netip.AddrFrom16([16]byte(packet[8:24]))
		dst = netip.AddrFrom16([16]byte(packet[24:40]))
	default:
		return
	}
	if proto != 6 && proto != 17 {
		return
	}
	if len(packet) < headerLen+4 {
		return
	}
	sport = uint16(packet[headerLen])<<8 | uint16(packet[headerLen+1])
	dport = uint16(packet[headerLen+2])<<8 | uint16(packet[headerLen+3])
	return src, dst, proto, sport, dport, true
}

func tcpClosing(packet []byte) bool {
	tcp, _, ok := tcpHeader(packet)
	if !ok || len(tcp) < 14 {
		return false
	}
	return tcp[13]&0x05 != 0
}
