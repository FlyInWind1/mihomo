//go:build with_gvisor && !no_tailscale

package outbound

import (
	"io"
	"os"
	"sync"

	"github.com/metacubex/mihomo/component/tailnet"
	wgtun "github.com/metacubex/tailscale-wireguard-go/tun"
)

// tailnetDevice is the tun tsnet reads and writes. Write goes to the Android
// VPN tun. Read returns replies to packets this node wrote to the host.
type tailnetDevice struct {
	bridge    *tailnet.Bridge
	events    chan wgtun.Event
	closeOnce sync.Once
}

func newTailnetDevice(bridge *tailnet.Bridge) *tailnetDevice {
	device := &tailnetDevice{
		bridge: bridge,
		events: make(chan wgtun.Event, 1),
	}
	device.events <- wgtun.EventUp
	return device
}

func (d *tailnetDevice) File() *os.File { return nil }

func (d *tailnetDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, io.ErrShortBuffer
	}
	for {
		packet, err := d.bridge.Read()
		if err != nil {
			return 0, err
		}
		if len(bufs[0]) < offset+len(packet) {
			continue
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

func (d *tailnetDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		// A tun restart closes the current descriptor. Drop that write instead
		// of failing the WireGuard device.
		_ = tailnet.WriteKernel(buf[offset:])
	}
	return len(bufs), nil
}

func (d *tailnetDevice) MTU() (int, error)          { return tailnetMTU, nil }
func (d *tailnetDevice) Name() (string, error)      { return "tailscale0", nil }
func (d *tailnetDevice) Events() <-chan wgtun.Event { return d.events }
func (d *tailnetDevice) BatchSize() int             { return 1 }

func (d *tailnetDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.events)
		d.bridge.Close()
	})
	return nil
}

const tailnetMTU = 1280
