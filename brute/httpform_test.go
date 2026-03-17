package brute

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteHTTPFormSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("username") == "admin" && r.FormValue("password") == "secret" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome, admin!"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Invalid credentials"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{
		"url":  "/login",
		"body": "username=%U&password=%W",
		"fail": "Invalid credentials",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteHTTPFormFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Invalid credentials"))
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "wrong", 5*time.Second, cm, ModuleParams{
		"url":  "/login",
		"body": "username=%U&password=%W",
		"fail": "Invalid credentials",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteHTTPFormSuccessMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("user") == "admin" && r.FormValue("pass") == "correct" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Dashboard - Welcome"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Login failed"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	// Using success string instead of fail string
	result := BruteHTTPForm(host, port, "admin", "correct", 5*time.Second, cm, ModuleParams{
		"url":     "/login",
		"body":    "user=%U&pass=%W",
		"success": "Dashboard",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success with success match, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormSuccessMatchMiss(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Login failed"))
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "wrong", 5*time.Second, cm, ModuleParams{
		"url":     "/login",
		"body":    "user=%U&pass=%W",
		"success": "Dashboard",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure when success string not found")
	}
}

func TestBruteHTTPFormGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("user") == "admin" && r.URL.Query().Get("pass") == "secret" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Invalid"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{
		"url":    "/login",
		"body":   "user=%U&pass=%W",
		"fail":   "Invalid",
		"method": "GET",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success via GET, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormWithCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		if cookie != "session=abc123" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("No session"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome"))
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{
		"url":    "/login",
		"body":   "user=%U&pass=%W",
		"fail":   "No session",
		"cookie": "session=abc123",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success with cookie, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormFollowRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		if r.URL.Path == "/dashboard" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Dashboard Welcome"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{
		"url":     "/login",
		"body":    "user=%U&pass=%W",
		"success": "Dashboard",
		"follow":  "true",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success after following redirect, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormConnectionFailure(t *testing.T) {
	cm := newTestCM()

	result := BruteHTTPForm("127.0.0.1", 1, "admin", "pass", 2*time.Second, cm, ModuleParams{
		"url":  "/login",
		"body": "user=%U&pass=%W",
		"fail": "Invalid",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure")
	}
}

func TestBruteHTTPFormMissingURL(t *testing.T) {
	cm := newTestCM()

	result := BruteHTTPForm("127.0.0.1", 80, "admin", "pass", 5*time.Second, cm, ModuleParams{
		"body": "user=%U&pass=%W",
		"fail": "Invalid",
	})

	if result.AuthSuccess {
		t.Fatal("expected failure without url param")
	}
	if result.Error == nil {
		t.Fatal("expected error about missing url")
	}
}

func TestBruteHTTPFormURLEncoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// ParseForm correctly decodes URL-encoded values, so we check
		// that the raw form values match the original (decoded) credentials.
		if r.FormValue("user") == "admin" && r.FormValue("pass") == "foo&bar=baz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Invalid credentials"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "foo&bar=baz", 5*time.Second, cm, ModuleParams{
		"url":  "/login",
		"body": "user=%U&pass=%W",
		"fail": "Invalid credentials",
	})

	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
	if !result.AuthSuccess {
		t.Fatalf("expected auth success with URL-encoded special chars, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormNoEncodingForJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For JSON, credentials should NOT be URL-encoded
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		if string(body) == `{"user":"admin","pass":"foo&bar"}` {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Invalid"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTPForm(host, port, "admin", "foo&bar", 5*time.Second, cm, ModuleParams{
		"url":          "/login",
		"body":         `{"user":"%U","pass":"%W"}`,
		"fail":         "Invalid",
		"content-type": "application/json",
	})

	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
	if !result.AuthSuccess {
		t.Fatalf("expected auth success with raw JSON body, got error: %v", result.Error)
	}
}

func TestBruteHTTPFormRegistered(t *testing.T) {
	for _, svc := range []string{"http-form", "https-form"} {
		if !IsRegistered(svc) {
			t.Errorf("%s should be registered", svc)
		}
	}
}

func TestBruteHTTPFormHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("user") == "admin" && r.FormValue("pass") == "secret" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Invalid"))
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)

	// Create a CM that uses the test server's TLS client
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteHTTPForm(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{
		"url":   "/login",
		"body":  "user=%U&pass=%W",
		"fail":  "Invalid",
		"https": "true",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success over HTTPS, got error: %v", result.Error)
	}
}
