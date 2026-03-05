package brute

import (
	"fmt"
	"time"

	"github.com/mitchellh/go-vnc"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: password,
			},
		},
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		authSuccess bool
		connSuccess bool
	}
	done := make(chan result, 1)

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return false, false
	}

	go func() {
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		client, err := vnc.Client(conn, config)
		if err != nil {
			done <- result{false, true}
			return
		}
		client.Close()
		done <- result{true, true}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return r.authSuccess, r.connSuccess
		default:
			return false, false
		}
	case r := <-done:
		return r.authSuccess, r.connSuccess
	}
}

func init() { Register("vnc", BruteVNC) }
