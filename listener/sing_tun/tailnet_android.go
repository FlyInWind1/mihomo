//go:build android

package sing_tun

import (
	"github.com/metacubex/mihomo/component/tailnet"
	tun "github.com/metacubex/sing-tun"
)

// tailnetTun keeps the kernel tun available for packets tsnet writes to the
// host. A reply to one of those packets is returned to tsnet. Everything
// else stays with the proxy stack.
type tailnetTun struct {
	tun.Tun
}

func prepareTailnetTun(inner tun.Tun) tun.Tun {
	tailnet.AttachKernel(inner)
	return &tailnetTun{Tun: inner}
}

func (t *tailnetTun) Read(p []byte) (int, error) {
	for {
		n, err := t.Tun.Read(p)
		if n > 0 && tailnet.TakeReply(p[:n]) {
			if err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (t *tailnetTun) Close() error {
	tailnet.DetachKernel(t.Tun)
	return t.Tun.Close()
}
