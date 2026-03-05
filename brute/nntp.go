package brute

import (
	"fmt"
	"net/textproto"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteNNTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *textproto.Conn
		err    error
	}
	done := make(chan result, 1)
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
		select {
		case r := <-done:
			if r.client != nil {
				r.client.Close()
			}
			if r.err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: r.err}
			}
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		if r.client != nil {
			defer r.client.Close()
		}
		if r.err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: r.err}
		}
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	}
}

func init() { Register("nntp", BruteNNTP) }
