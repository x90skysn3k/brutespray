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

func startMockVMAuthdServer(t *testing.T, validUser, validPass string, requireSSL bool) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock VMAuthd server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleVMAuthdConn(conn, validUser, validPass, requireSSL)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleVMAuthdConn(conn net.Conn, validUser, validPass string, requireSSL bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if requireSSL {
		fmt.Fprintf(conn, "220 VMware Authentication Daemon SSL Required\r\n")
		// We can't easily do TLS in the mock without certs, so just close
		return
	}

	fmt.Fprintf(conn, "220 VMware Authentication Daemon Version 1.10\r\n")

	r := bufio.NewReader(conn)
	var user string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "USER ") {
			user = strings.TrimPrefix(line, "USER ")
			fmt.Fprintf(conn, "331 Password required for %s.\r\n", user)
		} else if strings.HasPrefix(line, "PASS ") {
			pass := strings.TrimPrefix(line, "PASS ")
			if user == validUser && pass == validPass {
				fmt.Fprintf(conn, "230 User %s logged in.\r\n", user)
			} else {
				fmt.Fprintf(conn, "530 Login incorrect.\r\n")
			}
			return
		}
	}
}

func TestBruteVMAuthdSuccess(t *testing.T) {
	port, cleanup := startMockVMAuthdServer(t, "root", "vmware", false)
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteVMAuthd("127.0.0.1", port, "root", "vmware", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteVMAuthdFailure(t *testing.T) {
	port, cleanup := startMockVMAuthdServer(t, "root", "vmware", false)
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteVMAuthd("127.0.0.1", port, "root", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}
