package brute

import (
	"fmt"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		authSuccess bool
		connSuccess bool
	}
	done := make(chan result, 1)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{false, false}
			return
		}

		c, err := client.New(conn)
		if err != nil {
			done <- result{false, true}
			return
		}
		defer func() {
			_ = c.Logout()
		}()

		err = c.Login(user, password)
		if err != nil {
			done <- result{false, true}
			return
		}

		done <- result{true, true}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
	}
}

func init() { Register("imap", BruteIMAP) }
