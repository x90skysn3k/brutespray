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

func startMockIMAPServer(t *testing.T, handler func(conn net.Conn)) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock IMAP server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

// handleIMAPLogin handles a basic IMAP server supporting LOGIN command.
func handleIMAPLogin(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send greeting
	fmt.Fprintf(conn, "* OK [CAPABILITY IMAP4rev1 LOGIN STARTTLS] IMAP server ready\r\n")

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		// Parse tag and command
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])

		switch cmd {
		case "CAPABILITY":
			fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1 LOGIN STARTTLS\r\n")
			fmt.Fprintf(conn, "%s OK CAPABILITY completed\r\n", tag)

		case "LOGIN":
			if len(parts) < 3 {
				fmt.Fprintf(conn, "%s BAD Missing arguments\r\n", tag)
				continue
			}
			// Parse LOGIN user password
			loginArgs := strings.SplitN(parts[2], " ", 2)
			if len(loginArgs) < 2 {
				fmt.Fprintf(conn, "%s BAD Missing password\r\n", tag)
				continue
			}
			user := strings.Trim(loginArgs[0], "\"")
			pass := strings.Trim(loginArgs[1], "\"")
			if user == validUser && pass == validPass {
				fmt.Fprintf(conn, "%s OK LOGIN completed\r\n", tag)
			} else {
				fmt.Fprintf(conn, "%s NO LOGIN failed\r\n", tag)
			}

		case "LOGOUT":
			fmt.Fprintf(conn, "* BYE IMAP server logging out\r\n")
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return

		default:
			fmt.Fprintf(conn, "%s BAD Unknown command\r\n", tag)
		}
	}
}

// Note: these tests skip the race detector because the go-imap client
// library has an internal race in its reader goroutine (client.go:203
// vs client.go:223). This is a known upstream issue, not a bug in our code.

func TestBruteIMAPLoginSuccess(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping under race detector: go-imap library has known internal data race")
	}

	port, cleanup := startMockIMAPServer(t, func(conn net.Conn) {
		handleIMAPLogin(conn, "imapuser", "imappass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteIMAP("127.0.0.1", port, "imapuser", "imappass", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteIMAPLoginFailure(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping under race detector: go-imap library has known internal data race")
	}

	port, cleanup := startMockIMAPServer(t, func(conn net.Conn) {
		handleIMAPLogin(conn, "imapuser", "imappass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteIMAP("127.0.0.1", port, "imapuser", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}

func TestBruteIMAPBanner(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping under race detector: go-imap library has known internal data race")
	}

	port, cleanup := startMockIMAPServer(t, func(conn net.Conn) {
		handleIMAPLogin(conn, "user", "pass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteIMAP("127.0.0.1", port, "user", "wrong", 5*time.Second, cm, ModuleParams{})
	if result.Banner == "" {
		t.Fatal("expected non-empty banner with IMAP capabilities")
	}
}
