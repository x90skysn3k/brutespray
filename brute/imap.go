package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-imap/client"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	var (
		conn net.Conn
		err  error
	)

	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)

	if err != nil {
		tlsDialer := &tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: timeout,
			},
			Config: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		_, err = tlsDialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))

		if err != nil {
			return false, false
		} else {
			return false, true
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
