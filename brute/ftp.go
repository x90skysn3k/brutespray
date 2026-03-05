package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteFTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ftp.ServerConn
		err    error
	}
	done := make(chan result, 1)

	// Dial outside the goroutine to avoid a data race on conn.
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}

	go func() {
		// Set deadline to ensure the goroutine terminates if FTP negotiation hangs
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{nil, err}
			return
		}

		client, err := ftp.Dial(conn.RemoteAddr().String(), ftp.DialWithDialFunc(func(network, addr string) (net.Conn, error) { return conn, nil }))
		if err != nil {
			done <- result{nil, err}
			return
		}
		err = client.Login(user, password)
		done <- result{client, err}
	}()

	select {
	case <-timer.C:
		// Force the blocked goroutine to exit by killing the connection
		_ = conn.SetDeadline(time.Now())
		select {
		case result := <-done:
			conn.Close()
			if result.client != nil {
				_ = result.client.Quit()
			}
			if result.err != nil {
				return false, true
			}
			return true, true
		default:
			conn.Close()
			return false, false
		}
	case result := <-done:
		conn.Close()
		if result.client != nil {
			_ = result.client.Quit()
		}
		if result.err != nil {
			return false, true
		}
		return true, true
	}
}
