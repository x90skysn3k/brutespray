package brute

import (
	"fmt"
	"net/textproto"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteNNTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *textproto.Conn
		err    error
	}
	done := make(chan result)
	go func() {
		conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{nil, err}
			return
		}

		textConn := textproto.NewConn(conn)
		_, response, err := textConn.ReadResponse(200)
		if err != nil {
			_ = response
			done <- result{textConn, err}
			return
		}

		err = textConn.PrintfLine("AUTHINFO USER %s", user)
		if err != nil {
			done <- result{textConn, err}
			return
		}
		_, _, err = textConn.ReadResponse(381)
		if err != nil {
			done <- result{textConn, err}
			return
		}

		err = textConn.PrintfLine("AUTHINFO PASS %s", password)
		if err != nil {
			done <- result{textConn, err}
			return
		}
		_, _, err = textConn.ReadResponse(281)
		if err != nil {
			done <- result{textConn, err}
			return
		}

		done <- result{textConn, nil}
	}()

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.err != nil {
			return false, true
		}
		result.client.Close()
		return true, true
	}
}
