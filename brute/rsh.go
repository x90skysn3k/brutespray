package brute

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteRSH implements the rsh protocol (TCP port 514).
// Protocol: \0local_user\0remote_user\0command\0
func BruteRSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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
		cmd := params["cmd"]
		if cmd == "" {
			cmd = "id"
		}

		// rsh protocol: \0local_user\0remote_user\0command\0
		payload := fmt.Sprintf("\x00%s\x00%s\x00%s\x00", sanitizeCred(localUser), sanitizeCred(user), cmd)
		if _, err := conn.Write([]byte(payload)); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}

		// Read response — first byte 0 = success
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
		if strings.Contains(errLower, "permission") || strings.Contains(errLower, "denied") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func init() { Register("rsh", BruteRSH) }
