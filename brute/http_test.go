package brute

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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

func TestBruteHTTPUnauthenticatedSuccessDoesNotProveCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if !result.ConnectionSuccess {
		t.Fatalf("expected connection success for unauthenticated 2xx probe, got %+v", result)
	}
	if result.AuthSuccess {
		t.Fatalf("unauthenticated 2xx without WWW-Authenticate must not prove credential auth success, got %+v", result)
	}
}

func TestBruteHTTPForcedBasicUnauthenticatedSuccessDoesNotProveCredentials(t *testing.T) {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	var sawBasic atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == expected {
			sawBasic.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{"auth": "BASIC"})
	if !sawBasic.Load() {
		t.Fatal("expected forced BASIC credential attempt to send Authorization header")
	}
	if !result.ConnectionSuccess {
		t.Fatalf("expected connection success for forced BASIC 2xx response, got %+v", result)
	}
	if result.AuthSuccess {
		t.Fatalf("forced BASIC 2xx from a target that ignores Authorization must not prove credential auth success, got %+v", result)
	}
}

func TestBruteHTTPForcedBasicPostDoesNotSendUnauthenticatedPostPreflight(t *testing.T) {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	var unauthPOSTs atomic.Int32
	var authPOSTs atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == expected {
			if r.Method == http.MethodPost {
				authPOSTs.Add(1)
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodPost {
			unauthPOSTs.Add(1)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{
		"auth":   "BASIC",
		"method": "POST",
	})
	if got := unauthPOSTs.Load(); got != 0 {
		t.Errorf("forced BASIC POST must not preflight with unauthenticated POST; got %d unauthenticated POST request(s)", got)
	}
	if got := authPOSTs.Load(); got != 1 {
		t.Errorf("expected exactly one authenticated POST request, got %d", got)
	}
	if !result.AuthSuccess {
		t.Fatalf("expected authenticated POST to succeed, got %+v", result)
	}
}

func TestBruteHTTPForcedBasicPostIgnoresPublicFallbackGet(t *testing.T) {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	var unauthGETs atomic.Int32
	var unauthPOSTs atomic.Int32
	var authPOSTs atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Authorization") == expected && r.Method == http.MethodPost:
			authPOSTs.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Header.Get("Authorization") == "" && r.Method == http.MethodGet:
			unauthGETs.Add(1)
			_, _ = w.Write([]byte("public"))
		case r.Header.Get("Authorization") == "" && r.Method == http.MethodPost:
			unauthPOSTs.Add(1)
			t.Errorf("forced BASIC POST must not send an unauthenticated POST request")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected %s request with Authorization %q", r.Method, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{
		"auth":   "BASIC",
		"method": "POST",
	})
	if got := unauthGETs.Load(); got != 1 {
		t.Errorf("expected exactly one unauthenticated fallback GET probe, got %d", got)
	}
	if got := unauthPOSTs.Load(); got != 0 {
		t.Errorf("forced BASIC POST must not send unauthenticated POST; got %d request(s)", got)
	}
	if got := authPOSTs.Load(); got != 1 {
		t.Errorf("expected exactly one authenticated POST request, got %d", got)
	}
	if !result.ConnectionSuccess {
		t.Fatalf("expected connection success for authenticated POST, got %+v", result)
	}
	if !result.AuthSuccess {
		t.Fatalf("expected public fallback GET not to demote successful authenticated POST, got %+v", result)
	}
}

func TestBruteHTTPUnauthenticatedSuccessWithChallengeDoesNotProveCredentials(t *testing.T) {
	var requests atomic.Int32
	var sawAuth atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requests.Add(1) {
		case 1:
			if auth := r.Header.Get("Authorization"); auth != "" {
				t.Errorf("probe request unexpectedly sent Authorization header %q", auth)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="ignored"`)
			w.WriteHeader(http.StatusOK)
		case 2:
			if r.Header.Get("Authorization") != "" {
				sawAuth.Store(true)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected extra HTTP request %d", requests.Load())
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if requests.Load() != 2 {
		t.Fatalf("expected probe plus credential attempt, got %d request(s)", requests.Load())
	}
	if !sawAuth.Load() {
		t.Fatal("expected credential attempt to send Authorization header")
	}
	if !result.ConnectionSuccess {
		t.Fatalf("expected connection success for challenged 2xx probe, got %+v", result)
	}
	if result.AuthSuccess {
		t.Fatalf("challenged 2xx followed by unvalidated 2xx must not prove credential auth success, got %+v", result)
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
