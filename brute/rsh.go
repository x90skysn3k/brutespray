package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRSH implements the rsh protocol (TCP port 514).
// Protocol: \0local_user\0remote_user\0command\0
func BruteRSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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
		cmd := params["cmd"]
		if cmd == "" {
			cmd = "id"
		}

		// rsh protocol: \0local_user\0remote_user\0command\0
		payload := fmt.Sprintf("\x00%s\x00%s\x00%s\x00", sanitizeCred(localUser), sanitizeCred(user), cmd)
		if _, err := conn.Write([]byte(payload)); err != nil {
			done <- result{false, false}
			return
		}

		// Read response — first byte 0 = success
		r := bufio.NewReader(conn)
		b, err := r.ReadByte()
		if err != nil {
			done <- result{false, false}
			return
		}

		if b == 0 {
			done <- result{true, true}
			return
		}

		// Read error message
		errMsg, _ := r.ReadString('\n')
		errLower := strings.ToLower(errMsg)
		if strings.Contains(errLower, "permission") || strings.Contains(errLower, "denied") {
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

func init() { Register("rsh", BruteRSH) }
