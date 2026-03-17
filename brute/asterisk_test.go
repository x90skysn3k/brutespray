package brute

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func startMockAsteriskServer(t *testing.T, validUser, validPass string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock Asterisk AMI server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleAsteriskConn(conn, validUser, validPass)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleAsteriskConn(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send AMI banner
	fmt.Fprintf(conn, "Asterisk Call Manager/5.0.2\r\n")

	r := bufio.NewReader(conn)

	// Read the Login action block (terminated by blank line)
	headers := make(map[string]string)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	user := headers["Username"]
	pass := headers["Secret"]

	if user == validUser && pass == validPass {
		fmt.Fprintf(conn, "Response: Success\r\n")
		fmt.Fprintf(conn, "Message: Authentication accepted\r\n")
		fmt.Fprintf(conn, "\r\n")
	} else {
		fmt.Fprintf(conn, "Response: Error\r\n")
		fmt.Fprintf(conn, "Message: Authentication failed\r\n")
		fmt.Fprintf(conn, "\r\n")
	}

	// Read Logoff if sent
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			// End of Logoff action block
			fmt.Fprintf(conn, "Response: Goodbye\r\n")
			fmt.Fprintf(conn, "\r\n")
			return
		}
	}
}

func TestBruteAsteriskSuccess(t *testing.T) {
	port, cleanup := startMockAsteriskServer(t, "admin", "amp111")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteAsterisk("127.0.0.1", port, "admin", "amp111", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
	if !strings.Contains(result.Banner, "Asterisk") {
		t.Fatalf("expected banner to contain 'Asterisk', got %q", result.Banner)
	}
}

func TestBruteAsteriskFailure(t *testing.T) {
	port, cleanup := startMockAsteriskServer(t, "admin", "amp111")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteAsterisk("127.0.0.1", port, "admin", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}
