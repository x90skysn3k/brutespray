package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteVMAuthd(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
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

		stepDeadline := func() {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
		}

		stepDeadline()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			done <- result{false, false}
			return
		}
		response := string(buf[:n])

		var activeConn net.Conn = conn
		if strings.Contains(response, "SSL Required") {
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			activeConn = tlsConn
		}

		stepDeadline()
		cmd := fmt.Sprintf("USER %s\r\n", user)
		_, err = activeConn.Write([]byte(cmd))
		if err != nil {
			done <- result{false, true}
			return
		}

		stepDeadline()
		buf = make([]byte, 1024)
		n, err = activeConn.Read(buf)
		if err != nil {
			done <- result{false, true}
			return
		}
		response = string(buf[:n])
		if !strings.HasPrefix(response, "331 ") {
			done <- result{false, true}
			return
		}

		stepDeadline()
		cmd = fmt.Sprintf("PASS %s\r\n", password)
		_, err = activeConn.Write([]byte(cmd))
		if err != nil {
			done <- result{false, true}
			return
		}

		stepDeadline()
		buf = make([]byte, 1024)
		n, err = activeConn.Read(buf)
		if err != nil {
			done <- result{false, true}
			return
		}
		response = string(buf[:n])

		if strings.HasPrefix(response, "230 ") {
			done <- result{true, true}
		} else {
			done <- result{false, true}
		}
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

func init() { Register("vmauthd", BruteVMAuthd) }
