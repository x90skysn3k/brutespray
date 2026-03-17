package brute

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRexec implements the rexec protocol (TCP port 512).
// Protocol: \0username\0password\0command\0
func BruteRexec(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		// rexec protocol: \0username\0password\0command\0
		cmd := params["cmd"]
		if cmd == "" {
			cmd = "id"
		}
		payload := fmt.Sprintf("\x00%s\x00%s\x00%s\x00", sanitizeCred(user), sanitizeCred(password), cmd)
		if _, err := conn.Write([]byte(payload)); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}

		// Read response — first byte 0 = success, 1 = error
		r := bufio.NewReader(conn)
		b, err := r.ReadByte()
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		if b == 0 {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		}

		// Read error message
		errMsg, _ := r.ReadString('\n')
		errLower := strings.ToLower(errMsg)
		if strings.Contains(errLower, "permission") || strings.Contains(errLower, "denied") || strings.Contains(errLower, "invalid") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func init() { Register("rexec", BruteRexec) }
