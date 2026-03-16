package brute

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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
	os.WriteFile(keyPath, []byte("not a real key"), 0600)

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
	os.WriteFile(keyPath, keyData, 0600)

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
	os.WriteFile(keyPath, keyData, 0600)

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
	os.WriteFile(keyPath, keyData, 0600)

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	// First call — caches the key
	_ = BruteSSH("127.0.0.1", 1, "root", keyPath, 2*time.Second, cm, ModuleParams{
		"key": "true",
	})

	// Delete the file
	os.Remove(keyPath)

	// Second call — should use cached key, not fail with file-not-found
	result := BruteSSH("127.0.0.1", 1, "root", keyPath, 2*time.Second, cm, ModuleParams{
		"key": "true",
	})

	// Should NOT have a "reading SSH key" error since it's cached
	if result.Error != nil && strings.Contains(result.Error.Error(), "reading SSH key") {
		t.Fatal("expected cache to prevent re-reading deleted file")
	}
}
