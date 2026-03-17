package brute

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// errAPOPFallthrough signals that APOP authentication failed in auto mode
// and BrutePOP3 should reconnect and retry with USER/PASS.
var errAPOPFallthrough = errors.New("APOP failed, retry USER/PASS")

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

// pop3ExtractChallenge extracts an APOP challenge from a POP3 greeting.
// The challenge is the string between < and > (inclusive) in the greeting.
func pop3ExtractChallenge(greeting string) string {
	start := strings.Index(greeting, "<")
	if start < 0 {
		return ""
	}
	end := strings.Index(greeting[start:], ">")
	if end < 0 {
		return ""
	}
	return greeting[start : start+end+1]
}

// pop3AuthAPOP performs APOP authentication using the challenge from the greeting.
func pop3AuthAPOP(conn net.Conn, r *bufio.Reader, user, password, challenge string) (bool, error) {
	// APOP digest = MD5(challenge + password)
	hash := md5.Sum([]byte(challenge + password))
	digest := hex.EncodeToString(hash[:])

	_, err := fmt.Fprintf(conn, "APOP %s %s\r\n", user, digest)
	if err != nil {
		return false, err
	}
	resp, err := pop3ReadLine(r)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(resp, "+OK"), nil
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
// The authMethod parameter selects the mechanism: "PLAIN", "LOGIN", "APOP", or "" (auto/USER-PASS).
func pop3Auth(conn net.Conn, user, password, authMethod string, timeout time.Duration) *BruteResult {
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := pop3ReadLine(r)
	if err != nil || !strings.HasPrefix(greeting, "+OK") {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	// Extract APOP challenge from greeting if present
	challenge := pop3ExtractChallenge(greeting)

	// Query CAPA for banner enrichment
	capa := pop3GetCapa(conn, r)
	banner := greeting
	if capa != "" {
		banner = greeting + " [CAPA: " + capa + "]"
	}

	switch authMethod {
	case "APOP":
		// Forced APOP mode
		if challenge == "" {
			// No challenge in greeting, can't do APOP
			_, _ = fmt.Fprintf(conn, "QUIT\r\n")
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("APOP requested but no challenge in greeting"), Banner: banner}
		}
		ok, err := pop3AuthAPOP(conn, r, user, password, challenge)
		_, _ = fmt.Fprintf(conn, "QUIT\r\n")
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		return &BruteResult{AuthSuccess: ok, ConnectionSuccess: true, Banner: banner}

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

	default: // AUTO or USER (forced): try APOP if challenge present (unless USER forced), then USER/PASS
		if authMethod != "USER" && challenge != "" {
			ok, err := pop3AuthAPOP(conn, r, user, password, challenge)
			if err == nil && ok {
				_, _ = fmt.Fprintf(conn, "QUIT\r\n")
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
			}
			// APOP failed — signal caller to reconnect and retry with USER/PASS
			_, _ = fmt.Fprintf(conn, "QUIT\r\n")
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner, Error: errAPOPFallthrough}
		}

		// USER/PASS (default)
		_, err = fmt.Fprintf(conn, "USER %s\r\n", user)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		resp, err := pop3ReadLine(r)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		if !strings.HasPrefix(resp, "+OK") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil, Banner: banner}
		}

		// Send PASS
		_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
		}
		resp, err = pop3ReadLine(r)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
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
	// Normalize: accept USER, PLAIN, LOGIN, APOP; empty = auto
	switch authMethod {
	case "PLAIN", "LOGIN", "APOP":
		// use as-is
	default:
		authMethod = "" // auto mode
	}

	// Try plaintext first
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	result := pop3Auth(conn, user, password, authMethod, timeout)
	conn.Close()

	// APOP failed in auto mode — reconnect and retry with USER/PASS
	if errors.Is(result.Error, errAPOPFallthrough) {
		conn, err = cm.Dial("tcp", addr)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		result = pop3Auth(conn, user, password, "USER", timeout)
		conn.Close()
	}

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

	// APOP failed in auto mode over TLS — reconnect with TLS and retry USER/PASS
	if errors.Is(result.Error, errAPOPFallthrough) {
		conn, err = cm.Dial("tcp", addr)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		tlsConn = tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		result = pop3Auth(tlsConn, user, password, "USER", timeout)
		tlsConn.Close()
	}

	return result
}

func init() { Register("pop3", BrutePOP3) }
