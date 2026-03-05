package brute

import (
	"fmt"
	"time"

	"github.com/mitchellh/go-vnc"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
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
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
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
			return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
	}
}

func init() { Register("vnc", BruteVNC) }
