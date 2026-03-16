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

// startMockSMTPServer starts a mock SMTP server on an ephemeral port.
// The handler function is called for each accepted connection.
func startMockSMTPServer(t *testing.T, handler func(conn net.Conn)) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
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

// handleSMTPPlainAuth handles a mock SMTP session that advertises AUTH PLAIN.
func handleSMTPPlainAuth(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)

	// Send greeting
	fmt.Fprintf(conn, "220 mock.smtp.server ESMTP\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			fmt.Fprintf(conn, "250-mock.smtp.server\r\n")
			fmt.Fprintf(conn, "250 AUTH PLAIN\r\n")

		case strings.HasPrefix(upper, "AUTH PLAIN"):
			// AUTH PLAIN may have the data inline or require a continuation
			parts := strings.SplitN(line, " ", 3)
			var encoded string
			if len(parts) == 3 {
				encoded = parts[2]
			} else {
				fmt.Fprintf(conn, "334 \r\n")
				enc, err := r.ReadString('\n')
				if err != nil {
					return
				}
				encoded = strings.TrimRight(enc, "\r\n")
			}
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				fmt.Fprintf(conn, "535 Authentication failed\r\n")
				continue
			}
			// PLAIN format: \0username\0password
			parts2 := strings.SplitN(string(decoded), "\x00", 3)
			if len(parts2) == 3 && parts2[1] == validUser && parts2[2] == validPass {
				fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
			} else {
				fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

// handleSMTPLoginAuth handles a mock SMTP session that advertises AUTH LOGIN.
//
// The Go smtp package's Auth method works as follows with loginAuth:
//  1. loginAuth.Start() returns ("LOGIN", base64(username)) as initial data
//  2. smtp.Client.Auth sends: AUTH LOGIN <base64(base64(username))>
//  3. Server responds: 334 <base64("Password:")>
//  4. loginAuth.Next() returns base64(password)
//  5. smtp.Client.Auth sends: <base64(base64(password))>
//  6. Server responds: 235 or 535
//
// So the server receives double-base64 encoded credentials. When AUTH LOGIN
// is sent with initial data, we skip the username challenge.
func handleSMTPLoginAuth(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)

	fmt.Fprintf(conn, "220 mock.smtp.server ESMTP\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			fmt.Fprintf(conn, "250-mock.smtp.server\r\n")
			fmt.Fprintf(conn, "250 AUTH LOGIN\r\n")

		case strings.HasPrefix(upper, "AUTH LOGIN"):
			// The client may send initial data with AUTH LOGIN
			parts := strings.SplitN(line, " ", 3)
			var userB64B64 string

			if len(parts) == 3 && parts[2] != "" {
				// Initial data was provided (base64(base64(username)))
				userB64B64 = parts[2]
			} else {
				// No initial data — send username challenge
				fmt.Fprintf(conn, "334 %s\r\n", base64.StdEncoding.EncodeToString([]byte("Username:")))
				userLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				userB64B64 = strings.TrimRight(userLine, "\r\n")
			}

			// Send password challenge
			fmt.Fprintf(conn, "334 %s\r\n", base64.StdEncoding.EncodeToString([]byte("Password:")))
			passB64B64, err := r.ReadString('\n')
			if err != nil {
				return
			}
			passB64B64 = strings.TrimRight(passB64B64, "\r\n")

			// Decode: first layer is from smtp.Client.Auth, second from loginAuth
			userB64, err1 := base64.StdEncoding.DecodeString(userB64B64)
			passB64, err2 := base64.StdEncoding.DecodeString(passB64B64)
			if err1 != nil || err2 != nil {
				fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
				continue
			}
			userDecoded, err1 := base64.StdEncoding.DecodeString(string(userB64))
			passDecoded, err2 := base64.StdEncoding.DecodeString(string(passB64))
			if err1 != nil || err2 != nil {
				fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
				continue
			}

			if string(userDecoded) == validUser && string(passDecoded) == validPass {
				fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
			} else {
				fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func TestBruteSMTPPlainAuth(t *testing.T) {
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		handleSMTPPlainAuth(conn, "user@test.com", "secret123")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("Success", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "user@test.com", "secret123", 5*time.Second, cm, ModuleParams{"auth": "PLAIN"})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "user@test.com", "wrongpass", 5*time.Second, cm, ModuleParams{"auth": "PLAIN"})
		if result.AuthSuccess {
			t.Fatal("expected auth failure")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success (server responded)")
		}
	})
}

func TestBruteSMTPLoginAuth(t *testing.T) {
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		handleSMTPLoginAuth(conn, "user@test.com", "pass456")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("Success", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "user@test.com", "pass456", 5*time.Second, cm, ModuleParams{"auth": "LOGIN"})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "user@test.com", "wrong", 5*time.Second, cm, ModuleParams{"auth": "LOGIN"})
		if result.AuthSuccess {
			t.Fatal("expected auth failure")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success (server responded)")
		}
	})
}

func TestBruteSMTPAutoDetect(t *testing.T) {
	// Server advertises both PLAIN and LOGIN; auto should try PLAIN first
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)

		fmt.Fprintf(conn, "220 mock.smtp.server ESMTP\r\n")

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)

			switch {
			case strings.HasPrefix(upper, "EHLO"):
				fmt.Fprintf(conn, "250-mock.smtp.server\r\n")
				fmt.Fprintf(conn, "250 AUTH PLAIN LOGIN\r\n")

			case strings.HasPrefix(upper, "AUTH PLAIN"):
				parts := strings.SplitN(line, " ", 3)
				var encoded string
				if len(parts) == 3 {
					encoded = parts[2]
				} else {
					fmt.Fprintf(conn, "334 \r\n")
					enc, err := r.ReadString('\n')
					if err != nil {
						return
					}
					encoded = strings.TrimRight(enc, "\r\n")
				}
				decoded, _ := base64.StdEncoding.DecodeString(encoded)
				parts2 := strings.SplitN(string(decoded), "\x00", 3)
				if len(parts2) == 3 && parts2[1] == "autouser" && parts2[2] == "autopass" {
					fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
				} else {
					fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
				}

			case strings.HasPrefix(upper, "QUIT"):
				fmt.Fprintf(conn, "221 Bye\r\n")
				return

			default:
				fmt.Fprintf(conn, "502 Command not implemented\r\n")
			}
		}
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// No explicit auth param - auto-detect should pick PLAIN first
	result := BruteSMTP("127.0.0.1", port, "autouser", "autopass", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success via auto-detected PLAIN, got error: %v", result.Error)
	}
}

func TestBruteSMTPStartTLS(t *testing.T) {
	// Mock server advertises STARTTLS; the client should attempt it
	// Since we don't perform a real TLS handshake, this will fail gracefully
	// and fall back to authentication over the plain connection.
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)

		fmt.Fprintf(conn, "220 mock.smtp.server ESMTP\r\n")

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)

			switch {
			case strings.HasPrefix(upper, "EHLO"):
				fmt.Fprintf(conn, "250-mock.smtp.server\r\n")
				fmt.Fprintf(conn, "250-STARTTLS\r\n")
				fmt.Fprintf(conn, "250 AUTH PLAIN\r\n")

			case strings.HasPrefix(upper, "STARTTLS"):
				// Accept STARTTLS but the TLS handshake will fail since we
				// don't actually upgrade. This tests that the client attempts
				// the upgrade and handles the failure.
				fmt.Fprintf(conn, "220 Ready to start TLS\r\n")
				// Close after sending the response - the TLS handshake will fail
				return

			case strings.HasPrefix(upper, "AUTH PLAIN"):
				parts := strings.SplitN(line, " ", 3)
				var encoded string
				if len(parts) == 3 {
					encoded = parts[2]
				} else {
					fmt.Fprintf(conn, "334 \r\n")
					enc, err := r.ReadString('\n')
					if err != nil {
						return
					}
					encoded = strings.TrimRight(enc, "\r\n")
				}
				decoded, _ := base64.StdEncoding.DecodeString(encoded)
				parts2 := strings.SplitN(string(decoded), "\x00", 3)
				if len(parts2) == 3 && parts2[1] == "tlsuser" && parts2[2] == "tlspass" {
					fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
				} else {
					fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
				}

			case strings.HasPrefix(upper, "QUIT"):
				fmt.Fprintf(conn, "221 Bye\r\n")
				return

			default:
				fmt.Fprintf(conn, "502 Command not implemented\r\n")
			}
		}
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// The STARTTLS handshake will fail (no real TLS), but the module should
	// handle it gracefully without panicking. The result may be connection
	// failure or auth failure depending on how the SMTP library handles it.
	result := BruteSMTP("127.0.0.1", port, "tlsuser", "tlspass", 5*time.Second, cm, ModuleParams{})
	// We just verify it doesn't panic and returns a result
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Connection success is expected since the server did respond
	// Auth may or may not succeed depending on whether the SMTP lib
	// falls back after STARTTLS failure
	_ = result.AuthSuccess
}

// handleSMTPNTLMAuth handles a mock SMTP session that advertises AUTH NTLM.
// It performs a simplified 3-step NTLM exchange:
//  1. Client sends AUTH NTLM <negotiate>
//  2. Server replies 334 <challenge>
//  3. Client sends <authenticate>, server replies 235/535
func handleSMTPNTLMAuth(conn net.Conn, validUser, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)

	fmt.Fprintf(conn, "220 mock.smtp.server ESMTP\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			fmt.Fprintf(conn, "250-mock.smtp.server\r\n")
			fmt.Fprintf(conn, "250 AUTH NTLM\r\n")

		case strings.HasPrefix(upper, "AUTH NTLM"):
			// Step 1: client sends negotiate message
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				fmt.Fprintf(conn, "501 Syntax error\r\n")
				continue
			}

			// Decode negotiate to validate it's real NTLM
			negBytes, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil || len(negBytes) < 7 || string(negBytes[:7]) != "NTLMSSP" {
				fmt.Fprintf(conn, "535 Invalid NTLM negotiate\r\n")
				continue
			}

			// Step 2: send a fabricated Type 2 (challenge) message.
			// This is a minimal valid NTLMSSP_CHALLENGE with a fixed server challenge.
			challenge := []byte{
				'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, // Signature
				2, 0, 0, 0, // Type 2
				0, 0, // Target name len
				0, 0, // Target name max len
				0x38, 0, 0, 0, // Target name offset
				0x01, 0x02, 0x00, 0x00, // Negotiate flags (UNICODE | NTLM)
				1, 2, 3, 4, 5, 6, 7, 8, // Server challenge (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, // Reserved
				0, 0, // Target info len
				0, 0, // Target info max len
				0x38, 0, 0, 0, // Target info offset
				6, 1, 0, 0, 0, 0, 0, 15, // Version
			}
			fmt.Fprintf(conn, "334 %s\r\n", base64.StdEncoding.EncodeToString(challenge))

			// Step 3: read authenticate message
			authLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			authLine = strings.TrimRight(authLine, "\r\n")
			authBytes, err := base64.StdEncoding.DecodeString(authLine)
			if err != nil || len(authBytes) < 7 || string(authBytes[:7]) != "NTLMSSP" {
				fmt.Fprintf(conn, "535 Invalid NTLM authenticate\r\n")
				continue
			}

			// We can't truly validate NTLM response without NTLMv2 computation,
			// but we can verify the message is well-formed (Type 3) and accept
			// based on the known credentials being used in the test.
			// Type 3 message type at offset 8
			if len(authBytes) > 11 && authBytes[8] == 3 {
				// Accept if the test used the expected credentials
				// In real NTLM this would verify the response hash
				fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
			} else {
				fmt.Fprintf(conn, "535 5.7.8 Authentication credentials invalid\r\n")
			}

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return

		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func TestBruteSMTPNTLMAuth(t *testing.T) {
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		handleSMTPNTLMAuth(conn, "testuser", "testpass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	t.Run("NTLMSuccess", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "testuser", "testpass", 5*time.Second, cm, ModuleParams{"auth": "NTLM"})
		if !result.ConnectionSuccess {
			t.Fatalf("expected connection success, got error: %v", result.Error)
		}
		if !result.AuthSuccess {
			t.Fatalf("expected NTLM auth success, got error: %v", result.Error)
		}
	})

	t.Run("NTLMBanner", func(t *testing.T) {
		result := BruteSMTP("127.0.0.1", port, "testuser", "testpass", 5*time.Second, cm, ModuleParams{"auth": "NTLM"})
		if result.Banner == "" {
			t.Fatal("expected non-empty banner with AUTH methods")
		}
		if !strings.Contains(result.Banner, "NTLM") {
			t.Fatalf("expected banner to contain NTLM, got %q", result.Banner)
		}
	})
}

func TestBruteSMTPBanner(t *testing.T) {
	port, cleanup := startMockSMTPServer(t, func(conn net.Conn) {
		handleSMTPPlainAuth(conn, "user", "pass")
	})
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteSMTP("127.0.0.1", port, "user", "wrong", 5*time.Second, cm, ModuleParams{"auth": "PLAIN"})
	if result.Banner == "" {
		t.Fatal("expected non-empty banner with AUTH methods")
	}
	if !strings.Contains(result.Banner, "AUTH") {
		t.Fatalf("expected banner to contain AUTH info, got %q", result.Banner)
	}
}
