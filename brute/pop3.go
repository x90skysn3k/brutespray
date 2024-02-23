package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/knadh/go-pop3"
)

func BrutePOP3(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	options := []pop3.Opt{
		{Host: host, Port: port, DialTimeout: timeout},
		{Host: host, Port: port, TLSEnabled: true, DialTimeout: timeout},
	}
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}

	for _, opt := range options {
		var conn net.Conn
		var err error
		if opt.TLSEnabled {
			tlsDialer := &tls.Dialer{
				NetDialer: &net.Dialer{
					Timeout: timeout,
				},
				Config: &tls.Config{
					InsecureSkipVerify: true,
				},
			}

			conn, err = tlsDialer.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
			if err != nil {
				return false, true
			}
		} else {
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port), timeout)
			if err != nil {
				return false, true
			}
		}

		defer conn.Close()

		p := pop3.New(opt)
		c, err := p.NewConn()
		if err != nil {
			continue
		}

		defer func() {
			if err := c.Quit(); err != nil {
				_ = err
			}
		}()

		authDone := make(chan bool)
		go func() {
			err := c.Auth(user, password)
			authDone <- (err == nil)
		}()

		select {
		case authSuccess := <-authDone:
			if authSuccess {
				return true, true
			}

		case <-time.After(timeout):
		}
	}

	return false, false
}
