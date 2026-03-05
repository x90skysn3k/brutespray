package brute

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteTelnet(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		connection, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer connection.Close()

		// Propagate context cancellation to the connection
		go func() {
			<-ctx.Done()
			_ = connection.SetDeadline(time.Now())
		}()

		reader := bufio.NewReader(connection)

		stepDeadline := func(d time.Duration) {
			if d <= 0 || d > timeout {
				d = timeout
			}
			_ = connection.SetDeadline(time.Now().Add(d))
		}

		short := timeout / 3
		if short < 1500*time.Millisecond {
			short = 1500 * time.Millisecond
		}

		stepDeadline(short)
		_, _ = readUntil(reader, []string{"login:", "ogin:"}, 1024)

		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", user); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		stepDeadline(short)
		_, _ = readUntil(reader, []string{"Password:", "assword:"}, 1024)

		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", password); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "id\r\n"); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		stepDeadline(short)
		output, _ := readSome(reader, 2048)
		lower := strings.ToLower(output)
		if strings.Contains(lower, "login incorrect") || strings.Contains(lower, "authentication failure") || strings.Contains(lower, "incorrect") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		if strings.Contains(output, "uid=") || strings.Contains(output, "# ") || strings.Contains(output, "$ ") || strings.Contains(output, "/ #") {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func readUntil(reader *bufio.Reader, tokens []string, maxBytes int) (string, bool) {
	var b strings.Builder
	for b.Len() < maxBytes {
		by, err := reader.ReadByte()
		if err != nil {
			break
		}
		b.WriteByte(by)
		s := b.String()
		for _, t := range tokens {
			if strings.Contains(s, t) {
				return s, true
			}
		}
	}
	return b.String(), false
}

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

func init() { Register("telnet", BruteTelnet) }
