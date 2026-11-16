package brute

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteFTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	// Determine FTP mode: NORMAL (default), EXPLICIT (AUTH TLS), IMPLICIT (direct TLS)
	mode := strings.ToUpper(params["mode"])
	if mode == "" {
		// Auto-detect based on port
		if port == 990 {
			mode = "IMPLICIT"
		} else {
			mode = "NORMAL"
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ftp.ServerConn
		err    error
	}
	done := make(chan result, 1)

	addr := fmt.Sprintf("%s:%d", host, port)

	// Dial outside the goroutine to avoid a data race on conn.
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		// Set deadline to ensure the goroutine terminates if FTP negotiation hangs
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{nil, err}
			return
		}

		var client *ftp.ServerConn

		switch mode {
		case "IMPLICIT":
			// Wrap connection with TLS for implicit FTPS (port 990)
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			})
			if err := tlsConn.Handshake(); err != nil {
				done <- result{nil, err}
				return
			}
			client, err = ftp.Dial(addr,
				ftp.DialWithDialFunc(func(network, a string) (net.Conn, error) { return tlsConn, nil }))
			if err != nil {
				done <- result{nil, err}
				return
			}

		case "EXPLICIT":
			// Use AUTH TLS upgrade (library built-in support)
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			}
			client, err = ftp.Dial(addr,
				ftp.DialWithDialFunc(func(network, a string) (net.Conn, error) { return conn, nil }),
				ftp.DialWithExplicitTLS(tlsConfig))
			if err != nil {
				done <- result{nil, err}
				return
			}

		default: // NORMAL
			client, err = ftp.Dial(addr,
				ftp.DialWithDialFunc(func(network, a string) (net.Conn, error) { return conn, nil }))
			if err != nil {
				done <- result{nil, err}
				return
			}
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
			_ = conn.Close()
			if result.client != nil {
				_ = result.client.Quit()
			}
			if result.err != nil {
				return ftpAttemptResult(result.err)
			}
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		default:
			_ = conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case result := <-done:
		_ = conn.Close()
		if result.client != nil {
			_ = result.client.Quit()
		}
		if result.err != nil {
			return ftpAttemptResult(result.err)
		}
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	}
}

// ftpAttemptResult classifies an FTP attempt error. The library reports
// protocol-level server replies as *textproto.Error carrying an FTP status
// code — the server spoke FTP, so the connection succeeded and the failure
// is an auth failure. Bare transport errors (server closed before/without
// banner, reset, TLS failure) are connection failures: the circuit breaker
// must count them. Misclassifying them as auth failures let unreachable FTP
// hosts bypass -skip-policy / -max-conn-fails (issue #366 follow-up).
func ftpAttemptResult(err error) *BruteResult {
	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		// 530 = not logged in / user unknown → skip remaining passwords for this user
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, SkipUser: protoErr.Code == ftp.StatusNotLoggedIn, Error: err}
	}
	if strings.Contains(err.Error(), "530") {
		// USER rejected with 530: library returns the bare reply text
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, SkipUser: true, Error: err}
	}
	return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
}

func init() {
	Register("ftp", BruteFTP)
	Register("ftps", BruteFTP) // ftps defaults to EXPLICIT mode
}
