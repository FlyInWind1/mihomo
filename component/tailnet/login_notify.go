package tailnet

// OnLoginURL is set on Android to surface Tailscale interactive login URLs.
var OnLoginURL func(proxyName, url string)

func NotifyLoginURL(proxyName, url string) {
	if OnLoginURL == nil || url == "" {
		return
	}
	OnLoginURL(proxyName, url)
}
