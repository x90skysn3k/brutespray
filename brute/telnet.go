package brute

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTelnet(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		success bool
		conOk   bool
	}
	done := make(chan result, 1)

	go func() {
		connection, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{false, false}
			return
		}
		defer connection.Close()

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
			done <- result{false, true}
			return
		}

		stepDeadline(short)
		_, _ = readUntil(reader, []string{"Password:", "assword:"}, 1024)

		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", password); err != nil {
			done <- result{false, true}
			return
		}

		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "id\r\n"); err != nil {
			done <- result{false, true}
			return
		}

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
		done <- result{false, true}
	}()

	select {
	case <-timer.C:
		return false, false
	case r := <-done:
		return r.success, r.conOk
	}
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
