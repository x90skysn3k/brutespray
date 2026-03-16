package brute

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// startMockPOP3Server starts a mock POP3 server on an ephemeral port.
func startMockPOP3Server(t *testing.T, handler func(conn net.Conn)) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock POP3 server: %v", err)
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

// handlePOP3UserPass handles standard USER/PASS authentication.
func handlePOP3UserPass(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	// Send greeting
	fmt.Fprintf(conn, "+OK Mock POP3 server ready\r\n")

	var user string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "CAPA"):
			fmt.Fprintf(conn, "+OK Capability list follows\r\n")
			fmt.Fprintf(conn, "USER\r\n")
			fmt.Fprintf(conn, "SASL PLAIN LOGIN\r\n")
			fmt.Fprintf(conn, ".\r\n")

		case strings.HasPrefix(upper, "USER "):
			user = line[5:]
			fmt.Fprintf(conn, "+OK\r\n")

		case strings.HasPrefix(upper, "PASS "):
			pass := line[5:]
			if user == validUser && pass == validPass {
				fmt.Fprintf(conn, "+OK Logged in\r\n")
			} else {
				fmt.Fprintf(conn, "-ERR Authentication failed\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "+OK Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "-ERR Unknown command\r\n")
		}
	}
}

// handlePOP3PlainAuth handles SASL PLAIN authentication over POP3.
func handlePOP3PlainAuth(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	fmt.Fprintf(conn, "+OK Mock POP3 server ready\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "CAPA"):
			fmt.Fprintf(conn, "+OK Capability list follows\r\n")
			fmt.Fprintf(conn, "SASL PLAIN LOGIN\r\n")
			fmt.Fprintf(conn, ".\r\n")

		case strings.HasPrefix(upper, "AUTH PLAIN"):
			// Send continuation prompt
			fmt.Fprintf(conn, "+ \r\n")
			encoded, err := r.ReadString('\n')
			if err != nil {
				return
			}
			encoded = strings.TrimRight(encoded, "\r\n")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				fmt.Fprintf(conn, "-ERR Invalid base64\r\n")
				continue
			}
			// PLAIN format: \0user\0pass
			parts := strings.SplitN(string(decoded), "\x00", 3)
			if len(parts) == 3 && parts[1] == validUser && parts[2] == validPass {
				fmt.Fprintf(conn, "+OK Authentication successful\r\n")
			} else {
				fmt.Fprintf(conn, "-ERR Authentication failed\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "+OK Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "-ERR Unknown command\r\n")
		}
	}
}

// handlePOP3LoginAuth handles SASL LOGIN authentication over POP3.
func handlePOP3LoginAuth(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	fmt.Fprintf(conn, "+OK Mock POP3 server ready\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "CAPA"):
			fmt.Fprintf(conn, "+OK Capability list follows\r\n")
			fmt.Fprintf(conn, "SASL LOGIN\r\n")
			fmt.Fprintf(conn, ".\r\n")

		case strings.HasPrefix(upper, "AUTH LOGIN"):
			// Username challenge
			fmt.Fprintf(conn, "+ %s\r\n", base64.StdEncoding.EncodeToString([]byte("Username:")))
			userLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			userLine = strings.TrimRight(userLine, "\r\n")

			// Password challenge
			fmt.Fprintf(conn, "+ %s\r\n", base64.StdEncoding.EncodeToString([]byte("Password:")))
			passLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			passLine = strings.TrimRight(passLine, "\r\n")

			userDecoded, _ := base64.StdEncoding.DecodeString(userLine)
			passDecoded, _ := base64.StdEncoding.DecodeString(passLine)

			if string(userDecoded) == validUser && string(passDecoded) == validPass {
				fmt.Fprintf(conn, "+OK Authentication successful\r\n")
			} else {
				fmt.Fprintf(conn, "-ERR Authentication failed\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "+OK Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "-ERR Unknown command\r\n")
		}
	}
}

func TestBrutePOP3UserPass(t *testing.T) {
	port, cleanup := startMockPOP3Server(t, func(conn net.Conn) {
		handlePOP3UserPass(conn, "popuser", "poppass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("Success", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "popuser", "poppass", 5*time.Second, cm, ModuleParams{})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "popuser", "wrongpass", 5*time.Second, cm, ModuleParams{})
		if result.AuthSuccess {
			t.Fatal("expected auth failure")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success (server responded)")
		}
	})
}

func TestBrutePOP3PlainAuth(t *testing.T) {
	port, cleanup := startMockPOP3Server(t, func(conn net.Conn) {
		handlePOP3PlainAuth(conn, "plainuser", "plainpass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("Success", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "plainuser", "plainpass", 5*time.Second, cm, ModuleParams{"auth": "PLAIN"})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "plainuser", "wrong", 5*time.Second, cm, ModuleParams{"auth": "PLAIN"})
		if result.AuthSuccess {
			t.Fatal("expected auth failure")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success (server responded)")
		}
	})
}

func TestBrutePOP3LoginAuth(t *testing.T) {
	port, cleanup := startMockPOP3Server(t, func(conn net.Conn) {
		handlePOP3LoginAuth(conn, "loginuser", "loginpass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("Success", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "loginuser", "loginpass", 5*time.Second, cm, ModuleParams{"auth": "LOGIN"})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		result := BrutePOP3("127.0.0.1", port, "loginuser", "wrong", 5*time.Second, cm, ModuleParams{"auth": "LOGIN"})
		if result.AuthSuccess {
			t.Fatal("expected auth failure")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success (server responded)")
		}
	})
}

func TestBrutePOP3Banner(t *testing.T) {
	port, cleanup := startMockPOP3Server(t, func(conn net.Conn) {
		handlePOP3UserPass(conn, "user", "pass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BrutePOP3("127.0.0.1", port, "user", "wrong", 5*time.Second, cm, ModuleParams{})
	if result.Banner == "" {
		t.Fatal("expected non-empty banner with POP3 greeting")
	}
	if !strings.Contains(result.Banner, "Mock POP3") {
		t.Fatalf("expected banner to contain server greeting, got %q", result.Banner)
	}
}

func TestBrutePOP3TLSFallback(t *testing.T) {
	// The plaintext connection should succeed, so TLS fallback is not triggered.
	// To test the fallback path, we need the plaintext path to report
	// ConnectionSuccess=false. We do that with a server that immediately closes.
	port, cleanup := startMockPOP3Server(t, func(conn net.Conn) {
		// Send an invalid greeting that doesn't start with +OK
		// This causes pop3Auth to return ConnectionSuccess=false,
		// triggering the TLS fallback path.
		fmt.Fprintf(conn, "-ERR go away\r\n")
		conn.Close()
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 3*time.Second, "")

	// The module should try plaintext first, get connection failure, then try
	// TLS which will also fail since we don't have a TLS server. The overall
	// result should be connection failure without panicking.
	result := BrutePOP3("127.0.0.1", port, "user", "pass", 3*time.Second, cm, ModuleParams{})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	// ConnectionSuccess should be false since both plaintext and TLS failed
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure when both plaintext and TLS fail")
	}
}
