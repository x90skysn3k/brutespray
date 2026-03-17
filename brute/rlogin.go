package brute

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRlogin implements the rlogin protocol (TCP port 513).
// Protocol: \0local_user\0remote_user\0terminal/speed\0
func BruteRlogin(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

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
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}

		// Read response
		r := bufio.NewReader(conn)
		b, err := r.ReadByte()
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		// Null byte = success, then read banner
		if b == 0 {
			// Read some output to confirm access
			output := make([]byte, 1024)
			n, _ := r.Read(output)
			resp := strings.ToLower(string(output[:n]))
			if strings.Contains(resp, "denied") || strings.Contains(resp, "permission") || strings.Contains(resp, "incorrect") {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
			}
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		}

		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func init() { Register("rlogin", BruteRlogin) }
