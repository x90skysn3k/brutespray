package brute

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func newTestCM() *modules.ConnectionManager {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")
	return cm
}

func TestBruteHTTPAuthSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
		if auth == expected {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatal("expected auth success")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteHTTPAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "wrong", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}

func TestBruteHTTPConnectionFailure(t *testing.T) {
	cm := newTestCM()

	// Connect to a port that's not listening
	result := BruteHTTP("127.0.0.1", 1, "admin", "pass", 2*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure")
	}
}

func TestBruteHTTPRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("redirect should not count as auth success")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteHTTPServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("server error should not count as auth success")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (server responded)")
	}
}

// parseHostPort extracts host and port from a URL like "http://127.0.0.1:12345"
func parseHostPort(t *testing.T, url string) (string, int) {
	t.Helper()
	// Strip scheme
	addr := url
	if idx := strings.Index(addr, "://"); idx >= 0 {
		addr = addr[idx+3:]
	}
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("cannot parse host:port from %s", url)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("cannot parse port from %s: %v", url, err)
	}
	return parts[0], port
}
