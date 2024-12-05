package brute

import (
	"fmt"
	"strings"
	"time"

	"github.com/wenerme/astgo/ami"
	"github.com/x90skysn3k/brutespray/modules"
)

// this is very alpha and I have no idea if it even works
func BruteAsterisk(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	target := fmt.Sprintf("%s:%d", host, port)
	connManager, err := modules.NewConnectionManager(socks5, timeout)
	if err != nil {
		return false, false
	}

	service := "asterisk"
	conn, err := connManager.Dial("tcp", target)
	if err != nil {
		modules.PrintSocksError(service, fmt.Sprintf("%v", err))
		return false, false
	}
	defer conn.Close()

	boot := make(chan *ami.Message, 1)

	amiConn, err := ami.Connect(
		target,
		ami.WithAuth(user, password),
		ami.WithSubscribe(ami.SubscribeFullyBootedChanOnce(boot)),
	)
	if err != nil {
		return false, true
	}
	defer amiConn.Close()
	<-boot

	if strings.Contains(amiConn.Close().Error(), "Message: Authentication accepted") {
		return true, true
	} else {
		return false, true
	}
}
