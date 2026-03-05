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
func pop3Auth(conn net.Conn, user, password string, timeout time.Duration) (authSuccess bool, connSuccess bool) {
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	r := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := pop3ReadLine(r)
	if err != nil || !strings.HasPrefix(greeting, "+OK") {
		return false, false
	}

	// Send USER
	_, err = fmt.Fprintf(conn, "USER %s\r\n", user)
	if err != nil {
		return false, false
	}
	resp, err := pop3ReadLine(r)
	if err != nil {
		return false, false
	}
	if !strings.HasPrefix(resp, "+OK") {
		return false, true
	}

	// Send PASS
	_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
	if err != nil {
		return false, false
	}
	resp, err = pop3ReadLine(r)
	if err != nil {
		return false, false
	}

	// Send QUIT regardless
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")

	if strings.HasPrefix(resp, "+OK") {
		return true, true
	}
	return false, true
}

func BrutePOP3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Try plaintext first
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return false, false
	}
	authOK, connOK := pop3Auth(conn, user, password, timeout)
	conn.Close()
	if connOK {
		return authOK, true
	}

	// Try TLS
	conn, err = cm.Dial("tcp", addr)
	if err != nil {
		return false, false
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return false, false
	}
	authOK, connOK = pop3Auth(tlsConn, user, password, timeout)
	tlsConn.Close()
	return authOK, connOK
}
