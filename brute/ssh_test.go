package brute

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"golang.org/x/crypto/ssh"
)

func TestBruteSSHKeyMissingFile(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteSSH("127.0.0.1", 1, "root", "pass", 2*time.Second, cm, ModuleParams{
		"key": "/nonexistent/key",
	})

	// Missing key file should be ConnectionSuccess=true (not a network error)
	if result.ConnectionSuccess != true {
		t.Fatal("missing key file should report ConnectionSuccess=true (not a network issue)")
	}
	if result.AuthSuccess {
		t.Fatal("expected auth failure for missing key")
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "reading SSH key") {
		t.Fatalf("expected key read error, got: %v", result.Error)
	}
}

func TestBruteSSHKeyInvalidKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "badkey")
	_ = os.WriteFile(keyPath, []byte("not a real key"), 0600)

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteSSH("127.0.0.1", 1, "root", "pass", 2*time.Second, cm, ModuleParams{
		"key": keyPath,
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure for invalid key")
	}
	if !result.ConnectionSuccess {
		t.Fatal("invalid key should report ConnectionSuccess=true")
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "parsing SSH key") {
		t.Fatalf("expected parse error, got: %v", result.Error)
	}
}

func TestBruteSSHKeyValidUnencrypted(t *testing.T) {
	// Generate a valid Ed25519 key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyData := pem.EncodeToMemory(pemBlock)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	_ = os.WriteFile(keyPath, keyData, 0600)

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// key:true mode — password is the key path, no passphrase
	result := BruteSSH("127.0.0.1", 1, "root", keyPath, 2*time.Second, cm, ModuleParams{
		"key": "true",
	})

	// The key is valid but we can't connect to port 1 — should be connection failure
	// (the key parse succeeds, then the SSH dial fails)
	if result.AuthSuccess {
		t.Fatal("expected failure connecting to port 1")
	}
	// Connection should fail since nothing is listening on port 1
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure to port 1")
	}
}

func TestBruteSSHKeyPassphraseMode(t *testing.T) {
	// Generate a valid Ed25519 key with passphrase
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privKey, "", []byte("correctpass"))
	if err != nil {
		t.Fatal(err)
	}
	keyData := pem.EncodeToMemory(pemBlock)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519_enc")
	_ = os.WriteFile(keyPath, keyData, 0600)

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// Wrong passphrase
	result := BruteSSH("127.0.0.1", 1, "root", "wrongpass", 2*time.Second, cm, ModuleParams{
		"key": keyPath,
	})
	if result.AuthSuccess {
		t.Fatal("expected auth failure with wrong passphrase")
	}
	if !result.ConnectionSuccess {
		t.Fatal("wrong passphrase should be ConnectionSuccess=true (not a network issue)")
	}

	// Correct passphrase — key parses but connection to port 1 fails
	result = BruteSSH("127.0.0.1", 1, "root", "correctpass", 2*time.Second, cm, ModuleParams{
		"key": keyPath,
	})
	// Key parsed OK, but no SSH server on port 1
	if result.AuthSuccess {
		t.Fatal("expected failure connecting to port 1")
	}
	// Connection failure because nothing listens on port 1
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure to port 1")
	}
}

func TestBruteSSHKeyCache(t *testing.T) {
	// Verify the key cache works by reading a file, deleting it, then reading again
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyData := pem.EncodeToMemory(pemBlock)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cached_key")
	_ = os.WriteFile(keyPath, keyData, 0600)

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// First call — caches the key
	_ = BruteSSH("127.0.0.1", 1, "root", keyPath, 2*time.Second, cm, ModuleParams{
		"key": "true",
	})

	// Delete the file
	_ = os.Remove(keyPath)

	// Second call — should use cached key, not fail with file-not-found
	result := BruteSSH("127.0.0.1", 1, "root", keyPath, 2*time.Second, cm, ModuleParams{
		"key": "true",
	})

	// Should NOT have a "reading SSH key" error since it's cached
	if result.Error != nil && strings.Contains(result.Error.Error(), "reading SSH key") {
		t.Fatal("expected cache to prevent re-reading deleted file")
	}
}

// Issue #218: transient sshd drops (MaxStartups EOF/reset under high
// concurrency) must be classified as connection failures so the credential
// enters the missed-credential retry queue; only genuine auth rejection
// counts as "server answered the credential".
func TestSSHAuthRejectedClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"password denied (client_auth sentinel)", fmt.Errorf("ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), true},
		{"handshake-wrapped denial", fmt.Errorf("ssh: handshake failed: %w", fmt.Errorf("ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain")), true},
		{"maxstartups drop (EOF mid-handshake)", fmt.Errorf("ssh: handshake failed: EOF"), false},
		{"connection reset", fmt.Errorf("ssh: handshake failed: connection reset by peer"), false},
		{"kex failure", fmt.Errorf("ssh: handshake failed: ssh: no common algorithm"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := sshAuthRejected(tc.err); got != tc.want {
			t.Errorf("%s: sshAuthRejected(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// End-to-end for the same issue: a fake SSH server that completes the TCP
// accept then closes the connection (MaxStartups drop) must yield
// ConnectionSuccess=false so RunBrute retries and the missed-credential
// pass can replay the credential.
func TestBruteSSHTransientDropIsConnectionFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Drop without any SSH protocol, like a MaxStartups kill.
			_ = c.Close()
		}
	}()

	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")
	port := ln.Addr().(*net.TCPAddr).Port
	result := BruteSSH("127.0.0.1", port, "root", "chocolate", 2*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if result.ConnectionSuccess {
		t.Fatal("dropped handshake must be ConnectionSuccess=false (issue #218: must be retryable)")
	}
}

// A real (in-process) SSH server rejecting the password must keep
// ConnectionSuccess=true: the server engaged the credential, so retrying
// or tripping the connectivity breaker would be wrong.
func TestBruteSSHAuthDeniedKeepsConnectionSuccess(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("wrong password")
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, config)
			}(c)
		}
	}()

	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")
	port := ln.Addr().(*net.TCPAddr).Port
	result := BruteSSH("127.0.0.1", port, "root", "wrongpass", 2*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatalf("server-rejected credential must stay ConnectionSuccess=true, got err=%v", result.Error)
	}
}
