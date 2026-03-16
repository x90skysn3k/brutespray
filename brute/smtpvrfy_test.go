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

// startMockSMTPVRFYServer starts a mock SMTP server that supports VRFY, EXPN, and RCPT TO.
func startMockSMTPVRFYServer(t *testing.T, validUsers map[string]bool, validLists map[string]bool) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock SMTP VRFY server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSMTPVRFYConn(conn, validUsers, validLists)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleSMTPVRFYConn(conn net.Conn, validUsers map[string]bool, validLists map[string]bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	// Send greeting (must be 220 for textproto.ReadResponse)
	fmt.Fprintf(conn, "220 mock.smtp.vrfy ESMTP\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			fmt.Fprintf(conn, "250-mock.smtp.vrfy\r\n")
			fmt.Fprintf(conn, "250 VRFY\r\n")

		case strings.HasPrefix(upper, "VRFY "):
			user := strings.TrimSpace(line[5:])
			if validUsers[user] {
				fmt.Fprintf(conn, "250 %s <user@mock.smtp.vrfy>\r\n", user)
			} else {
				fmt.Fprintf(conn, "550 %s... User unknown\r\n", user)
			}

		case strings.HasPrefix(upper, "EXPN "):
			list := strings.TrimSpace(line[5:])
			if validLists[list] {
				fmt.Fprintf(conn, "250 %s <list@mock.smtp.vrfy>\r\n", list)
			} else {
				fmt.Fprintf(conn, "550 %s... List unknown\r\n", list)
			}

		case strings.HasPrefix(upper, "MAIL FROM:"):
			fmt.Fprintf(conn, "250 OK\r\n")

		case strings.HasPrefix(upper, "RCPT TO:"):
			// Extract the address between < and >
			addr := line[len("RCPT TO:"):]
			addr = strings.Trim(addr, " <>")
			// Check just the local part (before @) against valid users
			local := addr
			if idx := strings.Index(addr, "@"); idx >= 0 {
				local = addr[:idx]
			}
			if validUsers[local] {
				fmt.Fprintf(conn, "250 OK\r\n")
			} else {
				fmt.Fprintf(conn, "550 User unknown\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func TestSMTPVRFY(t *testing.T) {
	validUsers := map[string]bool{"admin": true, "root": true}
	port, cleanup := startMockSMTPVRFYServer(t, validUsers, nil)
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("ValidUser", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "admin", "", 5*time.Second, cm, ModuleParams{"verb": "VRFY"})
		if !result.AuthSuccess {
			t.Fatalf("expected VRFY success for valid user, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("InvalidUser", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "nonexistent", "", 5*time.Second, cm, ModuleParams{"verb": "VRFY"})
		if result.AuthSuccess {
			t.Fatal("expected VRFY failure for invalid user")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})
}

func TestSMTPEXPN(t *testing.T) {
	validLists := map[string]bool{"all-staff": true}
	port, cleanup := startMockSMTPVRFYServer(t, nil, validLists)
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("ValidList", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "all-staff", "", 5*time.Second, cm, ModuleParams{"verb": "EXPN"})
		if !result.AuthSuccess {
			t.Fatalf("expected EXPN success for valid list, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("InvalidList", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "nolist", "", 5*time.Second, cm, ModuleParams{"verb": "EXPN"})
		if result.AuthSuccess {
			t.Fatal("expected EXPN failure for invalid list")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})
}

func TestSMTPRCPT(t *testing.T) {
	validUsers := map[string]bool{"postmaster": true}
	port, cleanup := startMockSMTPVRFYServer(t, validUsers, nil)
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("ValidRecipient", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "postmaster", "", 5*time.Second, cm, ModuleParams{
			"verb":   "RCPT",
			"domain": "mock.smtp.vrfy",
		})
		if !result.AuthSuccess {
			t.Fatalf("expected RCPT success for valid recipient, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("InvalidRecipient", func(t *testing.T) {
		result := BruteSMTPVRFY("127.0.0.1", port, "nobody", "", 5*time.Second, cm, ModuleParams{
			"verb":   "RCPT",
			"domain": "mock.smtp.vrfy",
		})
		if result.AuthSuccess {
			t.Fatal("expected RCPT failure for invalid recipient")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})
}
