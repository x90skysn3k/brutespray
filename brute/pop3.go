package brute

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

// pop3ReadLine reads a single response line from the POP3 server.
func pop3ReadLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// pop3Auth attempts USER/PASS authentication over an existing connection.
func pop3Auth(conn net.Conn, user, password string, timeout time.Duration) *BruteResult {
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := pop3ReadLine(r)
	if err != nil || !strings.HasPrefix(greeting, "+OK") {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

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
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil}
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
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	}
	return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: nil}
}

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Try plaintext first
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	result := pop3Auth(conn, user, password, timeout)
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
	result = pop3Auth(tlsConn, user, password, timeout)
	tlsConn.Close()
	return result
}

func init() { Register("pop3", BrutePOP3) }
