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

func startMockTeamSpeakServer(t *testing.T, validUser, validPass string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TeamSpeak server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTeamSpeakConn(conn, validUser, validPass)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleTeamSpeakConn(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send TS3 banner
	fmt.Fprintf(conn, "TS3\r\n")
	fmt.Fprintf(conn, "Welcome to the TeamSpeak 3 ServerQuery interface.\r\n")

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "login") {
			// Parse: login client_login_name=USER client_login_password=PASS
			parts := strings.Fields(line)
			var user, pass string
			for _, p := range parts[1:] {
				if strings.HasPrefix(p, "client_login_name=") {
					user = strings.TrimPrefix(p, "client_login_name=")
				}
				if strings.HasPrefix(p, "client_login_password=") {
					pass = strings.TrimPrefix(p, "client_login_password=")
				}
			}

			if user == validUser && pass == validPass {
				fmt.Fprintf(conn, "error id=0 msg=ok\r\n")
			} else {
				fmt.Fprintf(conn, "error id=520 msg=invalid\\sloginname\\sor\\spassword\r\n")
			}
		} else if strings.HasPrefix(line, "quit") {
			return
		}
	}
}

func TestBruteTeamSpeakSuccess(t *testing.T) {
	port, cleanup := startMockTeamSpeakServer(t, "serveradmin", "secret123")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteTeamSpeak("127.0.0.1", port, "serveradmin", "secret123", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
	if !strings.Contains(result.Banner, "TS3") {
		t.Fatalf("expected banner to contain TS3, got %q", result.Banner)
	}
}

func TestBruteTeamSpeakFailure(t *testing.T) {
	port, cleanup := startMockTeamSpeakServer(t, "serveradmin", "secret123")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteTeamSpeak("127.0.0.1", port, "serveradmin", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}
