package brute

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// telnetFailurePatterns is a comprehensive list of failure indicators from
// real-world telnet servers (routers, switches, embedded devices, etc.).
var telnetFailurePatterns = []string{
	"incorrect", "invalid", "failed", "denied", "bad password",
	"authentication failed", "login failed", "login incorrect",
	"access denied", "wrong", "not allowed", "permission denied",
	"unable to authenticate", "information incomplete",
	"incorrect user/password", "please retry after",
	"bad password, bye-bye", "bad password,bye-bye",
	"login failure", "user was locked", "ip has been blocked",
	"cannot log on", "password is incorrect",
	"authorization failed", "error: authentication",
	"error: user was locked", "error: username or password",
	"% bad passwords", "% authentication failed", "% login failure",
	"bye-bye", "can't resolve symbol", "too many",
	"local: authentication failure", "please try it again",
	"username or password error", "user name or password is wrong",
	"закрыт", // Russian: "closed"
}

// loginPrompts are strings that indicate the server is requesting a username.
var loginPrompts = []string{
	"ogin:", "sername:", "user:", "login:", "user id:",
	"userid:", "account:", "user name:", "name:",
	"логин:",                   // Russian
	"user access verification", // Cisco
}

// loginPromptsExclude are substrings that should NOT be treated as login prompts.
var loginPromptsExclude = []string{"last login"}

// passwordPrompts are strings that indicate the server is requesting a password.
var passwordPrompts = []string{
	"asswor", "asscode", "ennwort", "passwd:", "pass:", "pwd:",
	"pin:", "enter password", "password for",
	"пароль:",     // Russian
	"contraseña:", // Spanish
}

// handleIAC processes telnet IAC (Interpret As Command) sequences from the
// read buffer, stripping them from data and sending appropriate responses.
// It accepts SGA and ECHO (needed for most servers) and rejects everything else.
func handleIAC(data []byte, conn interface{ Write([]byte) (int, error) }) []byte {
	const (
		iac  = 0xFF
		will = 0xFB
		wont = 0xFC
		do   = 0xFD
		dont = 0xFE
		sb   = 0xFA
		se   = 0xF0

		echo     = 0x01
		sga      = 0x03 // Suppress Go Ahead
		linemode = 0x22
	)

	var clean []byte
	i := 0
	for i < len(data) {
		if data[i] != iac || i+1 >= len(data) {
			clean = append(clean, data[i])
			i++
			continue
		}

		cmd := data[i+1]

		// Sub-negotiation: skip until IAC SE
		if cmd == sb {
			j := i + 2
			for j < len(data)-1 {
				if data[j] == iac && data[j+1] == se {
					j += 2
					break
				}
				j++
			}
			i = j
			continue
		}

		// WILL/WONT/DO/DONT require a 3rd byte (option code)
		if (cmd == will || cmd == wont || cmd == do || cmd == dont) && i+2 < len(data) {
			opt := data[i+2]
			switch cmd {
			case will:
				// Accept SGA, ECHO; reject others
				if opt == sga || opt == echo {
					_, _ = conn.Write([]byte{iac, do, opt})
				} else {
					_, _ = conn.Write([]byte{iac, dont, opt})
				}
			case do:
				// Accept SGA, LINEMODE; reject others
				if opt == sga || opt == linemode {
					_, _ = conn.Write([]byte{iac, will, opt})
				} else {
					_, _ = conn.Write([]byte{iac, wont, opt})
				}
			}
			i += 3
			continue
		}

		// Two-byte IAC commands (e.g., IAC IAC for literal 0xFF)
		if cmd == iac {
			clean = append(clean, iac)
			i += 2
			continue
		}

		// Skip other two-byte commands
		i += 2
	}
	return clean
}

// matchesPrompt checks if the text contains any of the given prompts (case-insensitive),
// excluding any matches that also contain an exclude string.
func matchesPrompt(text string, prompts []string, excludes []string) bool {
	lower := strings.ToLower(text)
	for _, ex := range excludes {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	for _, p := range prompts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func BruteTelnet(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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

		// Custom success string from -m success:STRING
		customSuccess := params["success"]

		// Read initial data, looking for login or password prompt
		stepDeadline(short)
		initialData, _ := readUntilTelnet(reader, connection, append(loginPrompts, passwordPrompts...), loginPromptsExclude, 2048)
		bannerText := initialData

		// Password-only mode: if we see a password prompt before any login prompt,
		// skip sending the username (handles Cisco, Juniper, embedded devices).
		initialLower := strings.ToLower(initialData)
		passwordOnly := false
		for _, pp := range passwordPrompts {
			if strings.Contains(initialLower, pp) {
				// Check that no login prompt appears before this password prompt
				hasLoginBefore := false
				ppIdx := strings.Index(initialLower, pp)
				for _, lp := range loginPrompts {
					lpIdx := strings.Index(initialLower, lp)
					if lpIdx >= 0 && lpIdx < ppIdx {
						// Check excludes
						excluded := false
						for _, ex := range loginPromptsExclude {
							if strings.Contains(initialLower, ex) {
								excluded = true
								break
							}
						}
						if !excluded {
							hasLoginBefore = true
							break
						}
					}
				}
				if !hasLoginBefore {
					passwordOnly = true
					break
				}
			}
		}

		if !passwordOnly {
			// Send username
			stepDeadline(short)
			if _, err := fmt.Fprintf(connection, "%s\r\n", user); err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: bannerText}
			}

			// Wait for password prompt
			stepDeadline(short)
			_, _ = readUntilTelnet(reader, connection, passwordPrompts, nil, 1024)
		}

		// Send password
		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "%s\r\n", password); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: bannerText}
		}

		// Send a command to check if we're authenticated
		stepDeadline(short)
		if _, err := fmt.Fprintf(connection, "id\r\n"); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: bannerText}
		}

		// Read response and check for success/failure
		stepDeadline(short)
		output, _ := readSomeTelnet(reader, connection, 2048)
		lower := strings.ToLower(output)

		// Check custom success string first
		if customSuccess != "" {
			if strings.Contains(strings.ToLower(output), strings.ToLower(customSuccess)) {
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: bannerText}
			}
		}

		// Check failure patterns
		for _, pattern := range telnetFailurePatterns {
			if strings.Contains(lower, pattern) {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: bannerText}
			}
		}

		// Check success indicators
		if strings.Contains(output, "uid=") || strings.Contains(output, "# ") || strings.Contains(output, "$ ") || strings.Contains(output, "/ #") {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: bannerText}
		}

		// Check for trailing shell prompt characters (>, %) indicating a shell
		trimmed := strings.TrimRight(output, " \t\r\n")
		if len(trimmed) > 0 {
			last := trimmed[len(trimmed)-1]
			if last == '>' || last == '%' {
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: bannerText}
			}
		}

		// Check if we got another login prompt (means auth failed)
		if matchesPrompt(output, loginPrompts, loginPromptsExclude) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: bannerText}
		}

		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: bannerText}
	})
}

// readUntilTelnet reads bytes until one of the tokens is found or maxBytes is reached.
// It handles IAC negotiation transparently.
func readUntilTelnet(reader *bufio.Reader, conn interface{ Write([]byte) (int, error) }, tokens []string, excludes []string, maxBytes int) (string, bool) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < maxBytes {
		_, err := reader.Read(buf)
		if err != nil {
			break
		}
		// Check for IAC
		if buf[0] == 0xFF {
			// Read more to handle the IAC sequence
			iacBuf := []byte{buf[0]}
			if peek, err := reader.ReadByte(); err == nil {
				iacBuf = append(iacBuf, peek)
				if peek == 0xFA || peek == 0xFB || peek == 0xFC || peek == 0xFD || peek == 0xFE {
					if peek == 0xFA {
						// Sub-negotiation: read until IAC SE
						for {
							sb, err := reader.ReadByte()
							if err != nil {
								break
							}
							iacBuf = append(iacBuf, sb)
							if sb == 0xF0 && len(iacBuf) >= 2 && iacBuf[len(iacBuf)-2] == 0xFF {
								break
							}
						}
					} else if peek >= 0xFB && peek <= 0xFE {
						// WILL/WONT/DO/DONT: read option byte
						if opt, err := reader.ReadByte(); err == nil {
							iacBuf = append(iacBuf, opt)
						}
					}
				}
			}
			cleaned := handleIAC(iacBuf, conn)
			b.Write(cleaned)
		} else {
			b.WriteByte(buf[0])
		}

		s := b.String()
		lower := strings.ToLower(s)
		for _, t := range tokens {
			if strings.Contains(lower, t) {
				// Check excludes
				excluded := false
				for _, ex := range excludes {
					if strings.Contains(lower, ex) {
						excluded = true
						break
					}
				}
				if !excluded {
					return s, true
				}
			}
		}
	}
	return b.String(), false
}

// readSomeTelnet reads available data up to maxBytes, handling IAC negotiation.
func readSomeTelnet(reader *bufio.Reader, conn interface{ Write([]byte) (int, error) }, maxBytes int) (string, bool) {
	var b strings.Builder
	buf := make([]byte, 256)
	for b.Len() < maxBytes {
		n, err := reader.Read(buf)
		if n > 0 {
			cleaned := handleIAC(buf[:n], conn)
			b.Write(cleaned)
		}
		if err != nil {
			break
		}
	}
	return b.String(), b.Len() > 0
}

func init() { Register("telnet", BruteTelnet) }
