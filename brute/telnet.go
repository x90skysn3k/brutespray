package brute

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTelnet(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	connection, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	defer connection.Close()

	err = connection.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, false
	}

	reader := bufio.NewReader(connection)

	// Helper to extend deadline between interactions
	extendDeadline := func() {
		_ = connection.SetDeadline(time.Now().Add(timeout))
	}

	// Read until we see a login prompt before sending the username (prompts often have no trailing newline)
	extendDeadline()
	_ = readUntilTokens(reader, connection, timeout, []string{"login:", "ogin:"}, 4096)

	// Send username followed by CRLF, which is more compatible with telnet servers
	extendDeadline()
	if _, err := fmt.Fprintf(connection, "%s\r\n", user); err != nil {
		return false, true
	}

	// Read until we see a password prompt
	extendDeadline()
	_ = readUntilTokens(reader, connection, timeout, []string{"Password:", "assword:"}, 4096)

	// Send password (blank password is supported by sending just CRLF)
	extendDeadline()
	if _, err := fmt.Fprintf(connection, "%s\r\n", password); err != nil {
		return false, true
	}

	// After login attempt, validate success by issuing a simple command
	// If login succeeded, shell should execute `id` and return output containing "uid="
	extendDeadline()
	if _, err := fmt.Fprintf(connection, "id\r\n"); err != nil {
		return false, true
	}

	extendDeadline()
	output := readForDuration(reader, connection, 1200*time.Millisecond)

	// Failure indicators commonly printed by login(1)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "login incorrect") || strings.Contains(lower, "authentication failure") || strings.Contains(lower, "incorrect") {
		return false, true
	}

	if strings.Contains(output, "uid=") {
		return true, true
	}

	// As a fallback, consider typical shell prompts as success
	if strings.Contains(output, "# ") || strings.Contains(output, "$ ") || strings.Contains(output, "/ #") {
		return true, true
	}

	return false, true
}

// readUntilTokens reads byte-by-byte until any token is found or the buffer reaches maxBytes or a read deadline fires.
// It returns true if a token was found, false otherwise. Non-fatal errors are ignored to allow lenient parsing.
func readUntilTokens(reader *bufio.Reader, conn net.Conn, overallTimeout time.Duration, tokens []string, maxBytes int) bool {
	deadline := time.Now().Add(overallTimeout)
	_ = conn.SetReadDeadline(deadline)
	var buf bytes.Buffer
	for buf.Len() < maxBytes {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		buf.WriteByte(b)
		s := buf.String()
		for _, t := range tokens {
			if strings.Contains(s, t) {
				return true
			}
		}
	}
	return false
}

// readForDuration reads all available data for approximately dur, stopping on deadline or minor errors.
func readForDuration(reader *bufio.Reader, conn net.Conn, dur time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(dur))
	var combined bytes.Buffer
	for {
		chunk, err := reader.ReadString('\n')
		if err != nil {
			// Try to salvage what we got so far
			if len(chunk) > 0 {
				combined.WriteString(chunk)
			}
			break
		}
		combined.WriteString(chunk)
		// Heuristic: if we see a shell prompt or uid= we can stop early
		s := combined.String()
		if strings.Contains(s, "uid=") || strings.Contains(s, "# ") || strings.Contains(s, "$ ") {
			break
		}
	}
	return combined.String()
}
