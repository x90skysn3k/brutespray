package brute

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// startScriptedTelnet starts a minimal telnet server with line-based
// responders. decoy=true models issue #366-comment devices: the outer login
// accepts anything and shows a fake shell prompt, but any command re-issues a
// login prompt (second authentication screen, no real access).
func startScriptedTelnet(t *testing.T, decoy bool) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = conn.Write([]byte("Welcome\r\nlogin: "))
				scanner := bufio.NewScanner(conn)
				scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
					if i := strings.Index(string(data), "\n"); i >= 0 {
						return i + 1, data[:i], nil
					}
					if atEOF {
						return 0, nil, nil
					}
					return 0, nil, nil
				})
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					switch {
					case line == "":
						if decoy {
							_, _ = conn.Write([]byte("\r\nlogin: "))
						} else {
							_, _ = conn.Write([]byte("\r\nbash-4.3# "))
						}
					case strings.HasPrefix(strings.ToLower(line), "id"):
						if decoy {
							_, _ = conn.Write([]byte("Router> "))
						} else {
							_, _ = conn.Write([]byte("uid=0(root) gid=0(root)\r\n# "))
						}
					default:
						// username or password line
						_, _ = conn.Write([]byte("Password: "))
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, func() { _ = listener.Close() }
}

func TestBruteTelnetDecoySecondScreenIsNotAuthSuccess(t *testing.T) {
	port, cleanup := startScriptedTelnet(t, true)
	defer cleanup()

	codes := []string{}
	origSink := modules.FindingSink
	origTUI := modules.TUIMode
	modules.TUIMode = true
	modules.FindingSink = func(severity, code, service, host, message, cve string) {
		codes = append(codes, code)
	}
	defer func() {
		modules.FindingSink = origSink
		modules.TUIMode = origTUI
	}()

	cm, err := modules.NewConnectionManager("", 5*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	result := BruteTelnet("127.0.0.1", port, "admin", "anything", 5*time.Second, cm, ModuleParams{})

	if result.AuthSuccess {
		t.Fatal("decoy second-screen device must not report auth success")
	}
	if !result.ConnectionSuccess {
		t.Fatal("device responded; expected connection success")
	}
	if len(codes) != 1 || codes[0] != "telnet-second-screen" {
		t.Fatalf("expected one telnet-second-screen finding, got %v", codes)
	}
}

func TestBruteTelnetRealShellStillSucceeds(t *testing.T) {
	port, cleanup := startScriptedTelnet(t, false)
	defer cleanup()

	codes := 0
	origSink := modules.FindingSink
	origTUI := modules.TUIMode
	modules.TUIMode = true
	modules.FindingSink = func(severity, code, service, host, message, cve string) {
		codes++
	}
	defer func() {
		modules.FindingSink = origSink
		modules.TUIMode = origTUI
	}()

	cm, err := modules.NewConnectionManager("", 5*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	result := BruteTelnet("127.0.0.1", port, "admin", "realpass", 5*time.Second, cm, ModuleParams{})

	if !result.AuthSuccess {
		t.Fatalf("real shell must still report auth success, got error=%v", result.Error)
	}
	if codes != 0 {
		t.Fatalf("no findings expected for real shell, got %d", codes)
	}
}
