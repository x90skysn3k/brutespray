package modules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadProxyListEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	_ = os.WriteFile(path, []byte(""), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err == nil {
		t.Fatal("expected error for empty proxy list")
	}
	if err.Error() != "proxy list is empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadProxyListComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comments.txt")
	content := "# this is a comment\n\n  \n# another comment\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err == nil {
		t.Fatal("expected error for proxy list with only comments")
	}
	if err.Error() != "proxy list is empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadProxyListNonexistent(t *testing.T) {
	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList("/nonexistent/proxy-list.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadProxyListValidEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.txt")
	content := "socks5://127.0.0.1:1080\n# comment\nsocks5://127.0.0.1:1081\nsocks5://127.0.0.1:1082\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cm.proxyList) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(cm.proxyList))
	}
	if len(cm.proxyDialers) != 3 {
		t.Fatalf("expected 3 dialers, got %d", len(cm.proxyDialers))
	}

	// Verify DialFunc was replaced (not nil)
	if cm.DialFunc == nil {
		t.Fatal("expected DialFunc to be set after loading proxy list")
	}
}

func TestLoadProxyListAuthProxy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth-proxies.txt")
	content := "socks5://user:pass@127.0.0.1:1080\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err != nil {
		t.Fatalf("unexpected error loading auth proxy: %v", err)
	}

	if len(cm.proxyList) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(cm.proxyList))
	}
}

func TestLoadProxyListInvalidURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.txt")
	content := "not-a-valid-scheme://badproxy\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err == nil {
		t.Fatal("expected error for invalid proxy URL scheme")
	}
}

func TestLoadProxyListBareSocks5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bare.txt")
	content := "127.0.0.1:1080\n127.0.0.1:1081\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	cm, err := NewConnectionManager("", 5*time.Second, "")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	err = cm.LoadProxyList(path)
	if err != nil {
		t.Fatalf("unexpected error for bare host:port proxies: %v", err)
	}

	if len(cm.proxyList) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(cm.proxyList))
	}
}
