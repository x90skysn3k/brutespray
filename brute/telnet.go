package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTelnet(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	// Align behavior with other modules: wrap whole attempt in a goroutine with an overall timer
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		success bool
		conOk   bool
	}
	done := make(chan result, 1)

	go func() {
		cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
		if err != nil {
			done <- result{false, false}
			return
		}

		connection, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{false, false}
			return
		}
		defer connection.Close()

		reader := bufio.NewReader(connection)

		// Helper to set short per-step deadlines to avoid long hangs between attempts
		stepDeadline := func(d time.Duration) {
			if d <= 0 || d > timeout {
				d = timeout
			}
			_ = connection.SetDeadline(time.Now().Add(d))
		}

		// Use short per-step timeouts to keep flow responsive
		short := timeout / 3
		if short < 1500*time.Millisecond {
			short = 1500 * time.Millisecond
		}

		// Best-effort: wait for a login prompt (not all telnetds require reading it first)
		stepDeadline(short)
		_, _ = readUntil(reader, []string{"login:", "ogin:"}, 1024)

		// Send username
		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", user); err != nil {
			done <- result{false, true}
			return
		}

		// Wait for password prompt
		stepDeadline(short)
		_, _ = readUntil(reader, []string{"Password:", "assword:"}, 1024)

		// Send password (supports blank password)
		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", password); err != nil {
			done <- result{false, true}
			return
		}

		// Issue id to confirm shell
		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "id\r\n"); err != nil {
			done <- result{false, true}
			return
		}

		// Read a limited amount of output and decide
		stepDeadline(short)
		output, _ := readSome(reader, 2048)
		lower := strings.ToLower(output)
		if strings.Contains(lower, "login incorrect") || strings.Contains(lower, "authentication failure") || strings.Contains(lower, "incorrect") {
			done <- result{false, true}
			return
		}
		if strings.Contains(output, "uid=") || strings.Contains(output, "# ") || strings.Contains(output, "$ ") || strings.Contains(output, "/ #") {
			done <- result{true, true}
			return
		}
		// If we reached here, connection worked but no success indicators
		done <- result{false, true}
	}()

	select {
	case <-timer.C:
		// Overall timeout reached (connection likely stalled)
		return false, false
	case r := <-done:
		return r.success, r.conOk
	}
}

// consumeUntil reads lines up to maxReads or until any of the tokens appear.
// It returns true if any token was found, false otherwise. Errors are ignored to remain lenient with telnet nuances.
func consumeUntil(reader *bufio.Reader, tokens []string, maxReads int, timeout time.Duration) bool {
	// Deprecated in favor of readUntil; kept for compatibility if referenced elsewhere
	out, ok := readUntil(reader, tokens, 2048)
	_ = out
	return ok
}

// readAccumulated keeps reading up to maxReads lines, accumulating the output.
// Any read error stops the loop and returns what has been accumulated.
func readAccumulated(reader *bufio.Reader, maxReads int, timeout time.Duration) string {
	// Deprecated in favor of readSome; kept for compatibility if referenced elsewhere
	out, _ := readSome(reader, 2048)
	return out
}

// readUntil reads up to maxBytes or until any token is found. It relies on connection deadlines
// set by the caller to avoid long blocking reads.
func readUntil(reader *bufio.Reader, tokens []string, maxBytes int) (string, bool) {
	var b strings.Builder
	found := false
	for b.Len() < maxBytes {
		by, err := reader.ReadByte()
		if err != nil {
			break
		}
		b.WriteByte(by)
		s := b.String()
		for _, t := range tokens {
			if strings.Contains(s, t) {
				found = true
				return s, true
			}
		}
	}
	return b.String(), found
}

// readSome reads up to maxBytes or until a read error occurs, returning what was read.
// Caller should set a deadline on the underlying connection.
func readSome(reader *bufio.Reader, maxBytes int) (string, bool) {
	var b strings.Builder
	for b.Len() < maxBytes {
		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 {
			b.WriteString(chunk)
		}
		if err != nil {
			break
		}
	}
	return b.String(), b.Len() > 0
}
