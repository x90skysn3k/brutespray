package brute

import (
	"context"
	"fmt"
	"net/textproto"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteNNTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		textConn := textproto.NewConn(conn)

		_, _, err := textConn.ReadResponse(200)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		err = textConn.PrintfLine("AUTHINFO USER %s", sanitizeCred(user))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		_, _, err = textConn.ReadResponse(381)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		err = textConn.PrintfLine("AUTHINFO PASS %s", sanitizeCred(password))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		_, _, err = textConn.ReadResponse(281)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("nntp", BruteNNTP) }
