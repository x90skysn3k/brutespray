package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteAsterisk(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read AMI banner (e.g., "Asterisk Call Manager/...")
	banner, err := r.ReadString('\n')
	if err != nil || !strings.Contains(banner, "Asterisk") {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	// Send Login action
	loginCmd := fmt.Sprintf("Action: Login\r\nUsername: %s\r\nSecret: %s\r\n\r\n", user, password)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	// Read response lines until we find Response: or hit blank line
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Response:") {
			if strings.Contains(line, "Success") {
				// Send Logoff
				_, _ = conn.Write([]byte("Action: Logoff\r\n\r\n"))
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil}
		}

		// Empty line marks end of response block
		if line == "" {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil}
		}
	}
}

func init() { Register("asterisk", BruteAsterisk) }
