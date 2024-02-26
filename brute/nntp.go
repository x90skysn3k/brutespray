package brute

import (
	"fmt"
	"net/textproto"
	"time"
)

func BruteNNTP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *textproto.Conn
		err    error
	}
	done := make(chan result)
	go func() {
		conn, err := textproto.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err == nil {
			defer conn.Close()
			_, _, err = conn.ReadResponse(200)
			if err == nil {
				err = conn.PrintfLine("AUTHINFO USER %s", user)
				if err == nil {
					_, _, err = conn.ReadResponse(381)
				}
				if err == nil {
					err = conn.PrintfLine("AUTHINFO PASS %s", password)
					if err == nil {
						_, _, err = conn.ReadResponse(281)
					}
				}
			}
		}
		done <- result{conn, err}
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
