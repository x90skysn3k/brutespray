package brute

import (
	"fmt"
	"strings"
	"time"

	"github.com/wenerme/astgo/ami"
	"github.com/x90skysn3k/brutespray/modules"
)

// BruteAsterisk is an alpha module — results may be inaccurate.
// NOTE: The ami library makes its own TCP connection; SOCKS5 proxy and
// interface binding do not apply. The CM dial serves as a reachability check.
func BruteAsterisk(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	target := fmt.Sprintf("%s:%d", host, port)

	// Reachability check via CM (proxy/interface aware)
	conn, err := cm.Dial("tcp", target)
	if err != nil {
		return false, false
	}
	conn.Close()

	if cm.Socks5 != "" {
		modules.PrintProxyWarning("asterisk")
	}

	boot := make(chan *ami.Message, 1)

	amiConn, err := ami.Connect(
		target,
		ami.WithAuth(user, password),
		ami.WithSubscribe(ami.SubscribeFullyBootedChanOnce(boot)),
	)
	if err != nil {
		return false, true
	}

	<-boot

	closeErr := amiConn.Close()
	if closeErr != nil && strings.Contains(closeErr.Error(), "Authentication accepted") {
		return true, true
	}

	return false, true
}
