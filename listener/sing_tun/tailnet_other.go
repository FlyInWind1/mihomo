//go:build !android

package sing_tun

import tun "github.com/metacubex/sing-tun"

func prepareTailnetTun(inner tun.Tun) tun.Tun { return inner }
