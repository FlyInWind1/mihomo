package tailnet

// Tailscale's safe TUN MTU. The Android VPN MTU is much larger, so TCP MSS
// on packets written to the host is clamped to what that MTU can carry.
const (
	safeMTU = 1280
	mssIPv4 = safeMTU - 20 - 20
	mssIPv6 = safeMTU - 40 - 20
)

// ClampTCPMSS lowers a SYN's MSS so replies fit through Tailscale.
// Packets that are not a TCP SYN are left unchanged.
func ClampTCPMSS(packet []byte) {
	tcp, maxMSS, ok := tcpHeader(packet)
	if !ok || tcp[13]&0x02 == 0 {
		return
	}
	headerLen := int(tcp[12]>>4) * 4
	if headerLen < 20 || len(tcp) < headerLen {
		return
	}
	opts := tcp[20:headerLen]
	for i := 0; i+1 < len(opts); {
		kind := opts[i]
		if kind == 0 {
			return
		}
		if kind == 1 {
			i++
			continue
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return
		}
		if kind == 2 && optLen == 4 {
			mss := int(opts[i+2])<<8 | int(opts[i+3])
			if mss > maxMSS {
				opts[i+2] = byte(maxMSS >> 8)
				opts[i+3] = byte(maxMSS)
				replaceChecksum(tcp, uint16(mss), uint16(maxMSS))
			}
			return
		}
		i += optLen
	}
}

func tcpHeader(packet []byte) (tcp []byte, maxMSS int, ok bool) {
	if len(packet) < 1 {
		return nil, 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, 0, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl+20 || packet[9] != 6 {
			return nil, 0, false
		}
		frag := int(packet[6]&0x1f)<<8 | int(packet[7])
		if frag != 0 {
			return nil, 0, false
		}
		return packet[ihl:], mssIPv4, true
	case 6:
		if len(packet) < 40+20 || packet[6] != 6 {
			return nil, 0, false
		}
		return packet[40:], mssIPv6, true
	default:
		return nil, 0, false
	}
}

// replaceChecksum applies the RFC 1624 update for one 16-bit field.
func replaceChecksum(tcp []byte, oldWord, newWord uint16) {
	if len(tcp) < 18 {
		return
	}
	sum := uint16(tcp[16])<<8 | uint16(tcp[17])
	x := uint32(^sum) + uint32(^oldWord) + uint32(newWord)
	x = (x & 0xffff) + (x >> 16)
	x = (x & 0xffff) + (x >> 16)
	sum = ^uint16(x)
	if sum == 0 {
		sum = 0xffff
	}
	tcp[16] = byte(sum >> 8)
	tcp[17] = byte(sum)
}
