package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRexec implements the rexec protocol (TCP port 512).
// Protocol: \0username\0password\0command\0
func BruteRexec(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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

		_ = conn.SetDeadline(time.Now().Add(timeout))

		// rexec protocol: \0username\0password\0command\0
		cmd := params["cmd"]
		if cmd == "" {
			cmd = "id"
		}
		payload := fmt.Sprintf("\x00%s\x00%s\x00%s\x00", sanitizeCred(user), sanitizeCred(password), cmd)
		if _, err := conn.Write([]byte(payload)); err != nil {
			done <- result{false, false}
			return
		}

		// Read response — first byte 0 = success, 1 = error
		r := bufio.NewReader(conn)
		b, err := r.ReadByte()
		if err != nil {
			done <- result{false, true}
			return
		}

		if b == 0 {
			done <- result{true, true}
			return
		}

		// Read error message
		errMsg, _ := r.ReadString('\n')
		errLower := strings.ToLower(errMsg)
		if strings.Contains(errLower, "permission") || strings.Contains(errLower, "denied") || strings.Contains(errLower, "invalid") {
			done <- result{false, true}
			return
		}
		done <- result{false, true}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}
	case r := <-done:
		return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess}
	}
}

func init() { Register("rexec", BruteRexec) }
