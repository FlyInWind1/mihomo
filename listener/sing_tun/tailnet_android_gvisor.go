//go:build android && with_gvisor

package sing_tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/mihomo/component/tailnet"
	tun "github.com/metacubex/sing-tun"
)

func (t *tailnetTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	gTun, ok := t.Tun.(tun.GVisorTun)
	if !ok {
		return 0, tun.ErrDrop
	}
	return gTun.WritePacket(pkt)
}

func (t *tailnetTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	gTun, ok := t.Tun.(tun.GVisorTun)
	if !ok {
		return nil, stack.NICOptions{}, tun.ErrDrop
	}
	endpoint, options, err := gTun.NewEndpoint()
	if err != nil || endpoint == nil {
		return endpoint, options, err
	}
	return &tailnetEndpoint{LinkEndpoint: endpoint}, options, nil
}

// tailnetEndpoint returns replies for packets tsnet wrote to the host.
// Other packets enter the proxy stack.
type tailnetEndpoint struct {
	stack.LinkEndpoint
}

func (e *tailnetEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.LinkEndpoint.Attach(nil)
		return
	}
	e.LinkEndpoint.Attach(tailnetDispatcher{NetworkDispatcher: dispatcher})
}

type tailnetDispatcher struct {
	stack.NetworkDispatcher
}

func (d tailnetDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if raw := gvisorPacket(pkt); len(raw) > 0 && tailnet.TakeReply(raw) {
		return
	}
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func gvisorPacket(pkt *stack.PacketBuffer) []byte {
	if pkt == nil || pkt.Data().Size() == 0 {
		return nil
	}
	return pkt.Data().AsRange().ToSlice()
}
