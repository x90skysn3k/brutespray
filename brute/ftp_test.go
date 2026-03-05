package brute

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

// startMockFTPServer starts a simple FTP server that accepts/rejects login.
// validUser/validPass control which credentials succeed.
func startMockFTPServer(t *testing.T, validUser, validPass string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock FTP server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			go handleFTPConn(conn, validUser, validPass)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleFTPConn(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send greeting
	fmt.Fprintf(conn, "220 Mock FTP Server Ready\r\n")

	buf := make([]byte, 4096)
	var user string

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// Handle multiple commands that may arrive in a single read
		lines := strings.Split(strings.TrimRight(string(buf[:n]), "\r\n"), "\r\n")
		for _, cmd := range lines {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}
			upper := strings.ToUpper(cmd)

			switch {
			case strings.HasPrefix(upper, "USER "):
				user = cmd[5:]
				fmt.Fprintf(conn, "331 Password required for %s\r\n", user)
			case strings.HasPrefix(upper, "PASS "):
				pass := cmd[5:]
				if user == validUser && pass == validPass {
					fmt.Fprintf(conn, "230 Login successful\r\n")
				} else {
					fmt.Fprintf(conn, "530 Login incorrect\r\n")
				}
			case strings.HasPrefix(upper, "QUIT"):
				fmt.Fprintf(conn, "221 Goodbye\r\n")
				return
			case strings.HasPrefix(upper, "FEAT"):
				fmt.Fprintf(conn, "211-Features:\r\n UTF8\r\n211 End\r\n")
			case strings.HasPrefix(upper, "TYPE"):
				fmt.Fprintf(conn, "200 Type set\r\n")
			case strings.HasPrefix(upper, "OPTS"):
				fmt.Fprintf(conn, "200 OK\r\n")
			default:
				fmt.Fprintf(conn, "502 Command not implemented\r\n")
			}
		}
	}
}

func TestBruteFTPAuthSuccess(t *testing.T) {
	port, cleanup := startMockFTPServer(t, "ftpuser", "ftppass")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")
	result := BruteFTP("127.0.0.1", port, "ftpuser", "ftppass", 5*time.Second, cm)

	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteFTPAuthFailure(t *testing.T) {
	port, cleanup := startMockFTPServer(t, "ftpuser", "ftppass")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")
	result := BruteFTP("127.0.0.1", port, "ftpuser", "wrongpass", 5*time.Second, cm)

	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}

func TestBruteFTPConnectionFailure(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")
	result := BruteFTP("127.0.0.1", 1, "user", "pass", 2*time.Second, cm)

	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure")
	}
}
