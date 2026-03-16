package brute

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBruteSVNAuthSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
		if auth == expected {
			w.Header().Set("DAV", "1, 2")
			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="SVN Repository"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteSVN(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatal("expected auth success")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteSVNAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="SVN Repository"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteSVN(host, port, "admin", "wrong", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteSVNWebDAVMultiStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "OPTIONS" {
			t.Errorf("expected OPTIONS method, got %s", r.Method)
		}
		w.Header().Set("DAV", "1, 2, version-control")
		w.WriteHeader(207) // Multi-Status
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteSVN(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatal("expected auth success on 207 Multi-Status")
	}
}

func TestBruteSVNConnectionFailure(t *testing.T) {
	cm := newTestCM()

	result := BruteSVN("127.0.0.1", 1, "admin", "pass", 2*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure")
	}
}

func TestBruteSVNBanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4 (SVN)")
		w.Header().Set("DAV", "1, 2")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteSVN(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{})
	if result.Banner == "" {
		t.Fatal("expected non-empty banner")
	}
	if result.Banner != "Apache/2.4 (SVN); DAV: 1, 2" {
		t.Fatalf("unexpected banner: %q", result.Banner)
	}
}

func TestBruteSVNRegistered(t *testing.T) {
	if !IsRegistered("svn") {
		t.Fatal("svn should be registered")
	}
}
