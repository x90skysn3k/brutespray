package brute

import (
	"fmt"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	var service = "imap"
	cm, err := modules.NewConnectionManager(socks5, timeout)
	if err != nil {
		modules.PrintSocksError(service, fmt.Sprintf("%v", err))
		return false, false
	}

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		modules.PrintSocksError(service, fmt.Sprintf("%v", err))
		return false, false
	}

	c, err := client.New(conn)
	if err != nil {
		return false, true
	}

	err = c.Login(user, password)
	if err != nil {
		return false, true
	}

	return true, true
}
