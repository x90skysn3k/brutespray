package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRlogin implements the rlogin protocol (TCP port 513).
// Protocol: \0local_user\0remote_user\0terminal/speed\0
func BruteRlogin(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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

		localUser := params["local-user"]
		if localUser == "" {
			localUser = user
		}
		terminal := params["terminal"]
		if terminal == "" {
			terminal = "xterm/9600"
		}

		// rlogin protocol: \0local_user\0remote_user\0terminal/speed\0
		payload := fmt.Sprintf("\x00%s\x00%s\x00%s\x00", sanitizeCred(localUser), sanitizeCred(user), terminal)
		if _, err := conn.Write([]byte(payload)); err != nil {
			done <- result{false, false}
			return
		}

		// Read response
		r := bufio.NewReader(conn)
		b, err := r.ReadByte()
		if err != nil {
			done <- result{false, false}
			return
		}

		// Null byte = success, then read banner
		if b == 0 {
			// Read some output to confirm access
			output := make([]byte, 1024)
			n, _ := r.Read(output)
			resp := strings.ToLower(string(output[:n]))
			if strings.Contains(resp, "denied") || strings.Contains(resp, "permission") || strings.Contains(resp, "incorrect") {
				done <- result{false, true}
				return
			}
			done <- result{true, true}
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

func init() { Register("rlogin", BruteRlogin) }
