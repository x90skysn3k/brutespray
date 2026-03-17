package brute

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteVMAuthd(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}
		response := string(buf[:n])

		var activeConn net.Conn = conn
		if strings.Contains(response, "SSL Required") {
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			activeConn = tlsConn
		}

		cmd := fmt.Sprintf("USER %s\r\n", sanitizeCred(user))
		_, err = activeConn.Write([]byte(cmd))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		buf = make([]byte, 1024)
		n, err = activeConn.Read(buf)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		response = string(buf[:n])
		if !strings.HasPrefix(response, "331 ") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		cmd = fmt.Sprintf("PASS %s\r\n", sanitizeCred(password))
		_, err = activeConn.Write([]byte(cmd))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		buf = make([]byte, 1024)
		n, err = activeConn.Read(buf)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		response = string(buf[:n])

		if strings.HasPrefix(response, "230 ") {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func init() { Register("vmauthd", BruteVMAuthd) }
