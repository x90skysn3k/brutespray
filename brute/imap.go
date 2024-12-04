package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/x90skysn3k/brutespray/modules"
	"golang.org/x/net/proxy"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	var service = "imap"
	var (
		conn net.Conn
		err  error
	)

	if socks5 != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5, nil, nil)
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}

		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}
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
