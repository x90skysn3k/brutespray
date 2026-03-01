package brute

import (
	"fmt"
	"time"

	"github.com/knadh/go-pop3"
	"github.com/x90skysn3k/brutespray/modules"
)

// tryPOP3Auth attempts POP3 authentication with the given options.
// Extracted from BrutePOP3 to avoid defer-in-loop issues (3.3 fix).
func tryPOP3Auth(opt pop3.Opt, user, password string, timeout time.Duration) (authSuccess bool, attempted bool) {
	p := pop3.New(opt)
	c, err := p.NewConn()
	if err != nil {
		return false, false
	}

	authDone := make(chan bool, 1)
	go func() {
		err := c.Auth(user, password)
		authDone <- (err == nil)
	}()

	var result bool
	select {
	case authSuccess := <-authDone:
		result = authSuccess
	case <-time.After(timeout):
		select {
		case authSuccess := <-authDone:
			result = authSuccess
		default:
			// Timeout with no response — clean up and report failure
			_ = c.Quit()
			return false, true
		}
	}

	_ = c.Quit()
	return result, true
}

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	// NOTE: The go-pop3 library doesn't support custom dialers, so SOCKS5
	// proxy and interface binding do not apply to the actual POP3 connection.
	// The CM dial here serves only as a reachability check.
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
		authSuccess, attempted := tryPOP3Auth(opt, user, password, timeout)
		if !attempted {
			continue
		}
		if authSuccess {
			return true, true
		}
		// Auth was attempted but failed — connection worked, don't try next option
		return false, true
	}

	return false, false
}
