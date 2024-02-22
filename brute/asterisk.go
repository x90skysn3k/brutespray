package brute

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/wenerme/astgo/ami"
)

// this is very alpha and I have no idea if it even works
func BruteAsterisk(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
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
