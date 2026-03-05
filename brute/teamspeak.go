package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTeamSpeak(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read TS3 banner: "TS3\n" followed by welcome message
	banner, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(banner), "TS3") {
		return false, false
	}
	// Read the welcome line
	_, _ = r.ReadString('\n')

	// Send login command
	loginCmd := fmt.Sprintf("login client_login_name=%s client_login_password=%s\n", user, password)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return false, false
	}

	// Read response
	resp, err := r.ReadString('\n')
	if err != nil {
		return false, false
	}
	resp = strings.TrimSpace(resp)

	// Send quit regardless
	_, _ = conn.Write([]byte("quit\n"))

	// Success: "error id=0 msg=ok"
	if strings.Contains(resp, "id=0") {
		return true, true
	}

	// Auth failure vs connection error
	if strings.Contains(resp, "error") {
		return false, true
	}

	return false, false
}

func init() { Register("teamspeak", BruteTeamSpeak) }
