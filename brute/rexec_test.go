package brute

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// startMockRexecServer starts a mock rexec server on an ephemeral port.
// The rexec protocol sends: \0username\0password\0command\0
// Response: \0 (success byte) + output, or \1 + error message.
func startMockRexecServer(t *testing.T, validUser, validPass string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock rexec server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleRexecConn(conn, validUser, validPass)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleRexecConn(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read the entire payload: \0user\0pass\0cmd\0
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Parse the null-delimited fields
	payload := string(buf[:n])
	// First byte should be \0
	if len(payload) == 0 || payload[0] != 0 {
		fmt.Fprintf(conn, "\x01Invalid protocol\n")
		return
	}

	// Split by null bytes (skip the leading null)
	parts := strings.SplitN(payload[1:], "\x00", 3)
	if len(parts) < 2 {
		fmt.Fprintf(conn, "\x01Invalid protocol\n")
		return
	}

	user := parts[0]
	pass := parts[1]

	if user == validUser && pass == validPass {
		// Success: \0 followed by output
		_, _ = conn.Write([]byte{0})
		fmt.Fprintf(conn, "uid=0(root) gid=0(root)\n")
	} else {
		// Failure: \1 followed by error message
		_, _ = conn.Write([]byte{1})
		fmt.Fprintf(conn, "Permission denied\n")
	}
}

func TestBruteRexecSuccess(t *testing.T) {
	port, cleanup := startMockRexecServer(t, "admin", "secret")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteRexec("127.0.0.1", port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteRexecFailure(t *testing.T) {
	port, cleanup := startMockRexecServer(t, "admin", "secret")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteRexec("127.0.0.1", port, "admin", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}
