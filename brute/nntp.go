package brute

import (
	"fmt"
	"net/textproto"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteNNTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	done := make(chan error, 1)
	go func() {
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		textConn := textproto.NewConn(conn)

		_, _, err := textConn.ReadResponse(200)
		if err != nil {
			done <- err
			return
		}

		err = textConn.PrintfLine("AUTHINFO USER %s", sanitizeCred(user))
		if err != nil {
			done <- err
			return
		}
		_, _, err = textConn.ReadResponse(381)
		if err != nil {
			done <- err
			return
		}

		err = textConn.PrintfLine("AUTHINFO PASS %s", sanitizeCred(password))
		if err != nil {
			done <- err
			return
		}
		_, _, err = textConn.ReadResponse(281)
		if err != nil {
			done <- err
			return
		}

		done <- nil
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case err := <-done:
			if err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
			}
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case err := <-done:
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	}
}

func init() { Register("nntp", BruteNNTP) }
