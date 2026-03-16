package brute

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// pop3ReadLine reads a single response line from the POP3 server.
func pop3ReadLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// pop3ReadMultiLine reads a multi-line POP3 response (used for CAPA).
// It reads until a line containing only "." is encountered.
func pop3ReadMultiLine(r *bufio.Reader) ([]string, error) {
	var lines []string
	for {
		line, err := pop3ReadLine(r)
		if err != nil {
			return lines, err
		}
		if line == "." {
			break
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// pop3GetCapa sends CAPA and returns the capability list as a single string.
func pop3GetCapa(conn net.Conn, r *bufio.Reader) string {
	_, err := fmt.Fprintf(conn, "CAPA\r\n")
	if err != nil {
		return ""
	}
	resp, err := pop3ReadLine(r)
	if err != nil || !strings.HasPrefix(resp, "+OK") {
		return ""
	}
	lines, err := pop3ReadMultiLine(r)
	if err != nil {
		return ""
	}
	return strings.Join(lines, " ")
}

// pop3AuthPlain performs SASL PLAIN authentication over POP3.
func pop3AuthPlain(conn net.Conn, r *bufio.Reader, user, password string) (bool, error) {
	_, err := fmt.Fprintf(conn, "AUTH PLAIN\r\n")
	if err != nil {
		return false, err
	}
	resp, err := pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	// Server should respond with "+" to indicate it's ready for the data
	if !strings.HasPrefix(resp, "+") {
		return false, nil
	}

	// PLAIN: base64(\0user\0password)
	plainData := fmt.Sprintf("\x00%s\x00%s", user, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(plainData))
	_, err = fmt.Fprintf(conn, "%s\r\n", encoded)
	if err != nil {
		return false, err
	}
	resp, err = pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(resp, "+OK"), nil
}

// pop3AuthLogin performs SASL LOGIN authentication over POP3.
func pop3AuthLogin(conn net.Conn, r *bufio.Reader, user, password string) (bool, error) {
	_, err := fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	if err != nil {
		return false, err
	}
	resp, err := pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	// Server should respond with "+" (challenge for username)
	if !strings.HasPrefix(resp, "+") {
		return false, nil
	}

	// Send base64-encoded username
	_, err = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(user)))
	if err != nil {
		return false, err
	}
	resp, err = pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	// Server should respond with "+" (challenge for password)
	if !strings.HasPrefix(resp, "+") {
		return false, nil
	}

	// Send base64-encoded password
	_, err = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(password)))
	if err != nil {
		return false, err
	}
	resp, err = pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(resp, "+OK"), nil
}

// pop3Auth attempts authentication over an existing POP3 connection.
// The authMethod parameter selects the mechanism: "PLAIN", "LOGIN", or "USER" (default).
func pop3Auth(conn net.Conn, user, password, authMethod string, timeout time.Duration) *BruteResult {
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := pop3ReadLine(r)
	if err != nil || !strings.HasPrefix(greeting, "+OK") {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	// Query CAPA for banner enrichment
	capa := pop3GetCapa(conn, r)
	banner := greeting
	if capa != "" {
		banner = greeting + " [CAPA: " + capa + "]"
	}

	switch authMethod {
	case "PLAIN":
		ok, err := pop3AuthPlain(conn, r, user, password)
		_, _ = fmt.Fprintf(conn, "QUIT\r\n")
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		return &BruteResult{AuthSuccess: ok, ConnectionSuccess: true, Banner: banner}

	case "LOGIN":
		ok, err := pop3AuthLogin(conn, r, user, password)
		_, _ = fmt.Fprintf(conn, "QUIT\r\n")
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		return &BruteResult{AuthSuccess: ok, ConnectionSuccess: true, Banner: banner}

	default: // USER/PASS (default)
		// Send USER
		_, err = fmt.Fprintf(conn, "USER %s\r\n", user)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		resp, err := pop3ReadLine(r)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		if !strings.HasPrefix(resp, "+OK") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil, Banner: banner}
		}

		// Send PASS
		_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		resp, err = pop3ReadLine(r)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}

		// Send QUIT regardless
		_, _ = fmt.Fprintf(conn, "QUIT\r\n")

		if strings.HasPrefix(resp, "+OK") {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil, Banner: banner}
	}
}

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Determine auth method from params
	authMethod := strings.ToUpper(params["auth"])
	// Normalize: empty or "USER" both use the default USER/PASS flow
	if authMethod != "PLAIN" && authMethod != "LOGIN" {
		authMethod = ""
	}

	// Try plaintext first
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	result := pop3Auth(conn, user, password, authMethod, timeout)
	conn.Close()
	if result.ConnectionSuccess {
		return result
	}

	// Try TLS
	conn, err = cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	result = pop3Auth(tlsConn, user, password, authMethod, timeout)
	tlsConn.Close()
	return result
}

func init() { Register("pop3", BrutePOP3) }
