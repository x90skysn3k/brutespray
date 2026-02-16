package brute

import (
	"fmt"
	"time"

	"github.com/knadh/go-pop3"
	"github.com/x90skysn3k/brutespray/modules"
)

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	// pop3 library creates its own connection using net.DialTimeout or tls.Dial
	// It doesn't seem to support custom dialer easily in the Opt struct.
	// But we can use NewConn() which might take a connection?
	// Checking library usage: pop3.New(opt) -> p.NewConn() creates connection.
	// If the library doesn't support custom dialer, we are stuck bypassing cm for the actual connection
	// unless we fork/modify the library or if it supports a dialer func.
	// Assuming we can't easily change the library behavior for now,
	// we will at least do the connectivity check with cm.

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	conn.Close()

	options := []pop3.Opt{
		{Host: host, Port: port, DialTimeout: timeout},
		{Host: host, Port: port, TLSEnabled: true, DialTimeout: timeout},
	}

	for _, opt := range options {
		// Note: This still bypasses proxy for the actual POP3 connection
		// fixing this requires library support or upstream changes.

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

		authDone := make(chan bool, 1)
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
			select {
			case authSuccess := <-authDone:
				if authSuccess {
					return true, true
				}
			default:
			}
		}
	}

	return false, false
}
