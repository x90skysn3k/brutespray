package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/knadh/go-pop3"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	defer conn.Close()

	options := []pop3.Opt{
		{Host: host, Port: port, DialTimeout: timeout},
		{Host: host, Port: port, TLSEnabled: true, DialTimeout: timeout},
	}

	for _, opt := range options {
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
			_, err = tlsDialer.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
			if err != nil {
				return false, true
			}
		} else {
			_, err = conn, nil
			_ = err
		}

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
