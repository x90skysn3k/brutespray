package brute

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBruteHTTPDigestAuth verifies Digest authentication end-to-end.
func TestBruteHTTPDigestAuth(t *testing.T) {
	const (
		validUser = "admin"
		validPass = "secret"
		realm     = "testrealm"
		nonce     = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Digest ") {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse the Digest response to validate credentials
		username := parseDigestField(auth, "username")
		respHash := parseDigestField(auth, "response")
		uri := parseDigestField(auth, "uri")
		nc := parseDigestField(auth, "nc")
		cnonce := parseDigestField(auth, "cnonce")

		// Compute expected response
		ha1 := fmt.Sprintf("%x", md5.Sum([]byte(username+":"+realm+":"+validPass)))
		ha2 := fmt.Sprintf("%x", md5.Sum([]byte(r.Method+":"+uri)))
		expected := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+nonce+":"+nc+":"+cnonce+":auth:"+ha2)))

		if username == validUser && respHash == expected {
			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)

	// Clear the HTTP auth cache to avoid leaking state between tests
	httpAuthCache = sync.Map{}

	cm := newTestCM()

	t.Run("CorrectCredentials", func(t *testing.T) {
		httpAuthCache = sync.Map{}
		result := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{"auth": "DIGEST"})
		if !result.AuthSuccess {
			t.Fatalf("expected auth success, got error: %v", result.Error)
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})

	t.Run("WrongCredentials", func(t *testing.T) {
		httpAuthCache = sync.Map{}
		result := BruteHTTP(host, port, validUser, "wrongpass", 5*time.Second, cm, ModuleParams{"auth": "DIGEST"})
		if result.AuthSuccess {
			t.Fatal("expected auth failure with wrong password")
		}
		if !result.ConnectionSuccess {
			t.Fatal("expected connection success")
		}
	})
}

// TestBruteHTTPAutoDetectBasic verifies that auto-detection picks Basic when
// the server advertises WWW-Authenticate: Basic.
func TestBruteHTTPAutoDetectBasic(t *testing.T) {
	httpAuthCache = sync.Map{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
		if auth == expected {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	// No explicit auth param - auto-detect should pick Basic
	result := BruteHTTP(host, port, "admin", "secret", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auto-detected Basic auth success, got error: %v", result.Error)
	}
}

// TestBruteHTTPAutoDetectDigest verifies that auto-detection picks Digest when
// the server advertises a Digest challenge.
func TestBruteHTTPAutoDetectDigest(t *testing.T) {
	httpAuthCache = sync.Map{}

	const (
		realm = "testrealm"
		nonce = "abc123"
	)

	var detectedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(auth, "Digest ") {
			detectedMethod = "DIGEST"
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
		t.Fatalf("expected auth success via auto-detected Digest, got error: %v", result.Error)
	}
	if detectedMethod != "DIGEST" {
		t.Fatalf("expected Digest auth method, got %q", detectedMethod)
	}
}

// TestBruteHTTPCustomPath verifies that params["dir"] directs requests to the
// correct path on the server.
func TestBruteHTTPCustomPath(t *testing.T) {
	httpAuthCache = sync.Map{}

	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:pass"))
		if auth == expected {
			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{
		"dir":  "/admin",
		"auth": "BASIC",
	})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if requestedPath != "/admin" {
		t.Fatalf("expected request path /admin, got %q", requestedPath)
	}
}

// TestBruteHTTPCustomMethod verifies that params["method"] = "POST" sends a POST request.
func TestBruteHTTPCustomMethod(t *testing.T) {
	httpAuthCache = sync.Map{}

	var requestedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedMethod = r.Method
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:pass"))
		if auth == expected {
			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "pass", 5*time.Second, cm, ModuleParams{
		"method": "POST",
		"auth":   "BASIC",
	})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if requestedMethod != "POST" {
		t.Fatalf("expected POST method, got %q", requestedMethod)
	}
}

// TestBruteHTTPBannerCapture verifies that the Server and WWW-Authenticate
// headers are captured in the result banner.
func TestBruteHTTPBannerCapture(t *testing.T) {
	httpAuthCache = sync.Map{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MockHTTP/1.0")
		w.Header().Set("WWW-Authenticate", `Basic realm="testbanner"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, "admin", "wrong", 5*time.Second, cm, ModuleParams{"auth": "BASIC"})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !strings.Contains(result.Banner, "MockHTTP/1.0") {
		t.Fatalf("expected banner to contain Server header, got %q", result.Banner)
	}
	if !strings.Contains(result.Banner, "Basic") {
		t.Fatalf("expected banner to contain WWW-Authenticate info, got %q", result.Banner)
	}
}

func TestBruteHTTPAutoDetectDigestRefreshesChallengeAfterCacheHit(t *testing.T) {
	httpAuthCache = sync.Map{}

	const (
		validUser = "admin"
		validPass = "secret"
		realm     = "cached-digest"
	)

	var challengeCount int
	var currentNonce string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Digest ") && validDigestAuth(r, auth, validUser, validPass, realm, currentNonce) {
			currentNonce = ""
			w.WriteHeader(http.StatusOK)
			return
		}

		challengeCount++
		currentNonce = fmt.Sprintf("nonce-%d", challengeCount)
		w.Header().Set("WWW-Authenticate", digestChallenge(realm, currentNonce))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	first := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{})
	if !first.AuthSuccess {
		t.Fatalf("first auto-detected Digest attempt should authenticate, got %+v", first)
	}

	second := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{})
	if !second.AuthSuccess {
		t.Fatalf("second auto-detected Digest attempt should fetch a fresh challenge and authenticate, got %+v", second)
	}

	if challengeCount != 2 {
		t.Fatalf("expected one Digest challenge per brute-force attempt, got %d", challengeCount)
	}
}

func TestBruteHTTPAutoDetectBasicThenDigestPathDoesNotUseHostCache(t *testing.T) {
	httpAuthCache = sync.Map{}

	const (
		validUser = "admin"
		validPass = "secret"
		realm     = "mixed-paths"
	)

	var digestChallengeCount int
	var digestNonce string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/basic":
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(validUser+":"+validPass))
			if r.Header.Get("Authorization") == expected {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="basic-path"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/digest":
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Digest ") && validDigestAuth(r, auth, validUser, validPass, realm, digestNonce) {
				w.WriteHeader(http.StatusOK)
				return
			}
			digestChallengeCount++
			digestNonce = fmt.Sprintf("path-nonce-%d", digestChallengeCount)
			w.Header().Set("WWW-Authenticate", digestChallenge(realm, digestNonce))
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	basic := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{"dir": "/basic"})
	if !basic.AuthSuccess {
		t.Fatalf("auto-detected Basic path should authenticate before testing Digest path, got %+v", basic)
	}

	digest := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{"dir": "/digest"})
	if !digest.AuthSuccess {
		t.Fatalf("auto-detected Digest path should not reuse Basic cache entry from /basic, got %+v", digest)
	}

	if digestChallengeCount != 1 {
		t.Fatalf("expected Digest path to be challenged once, got %d", digestChallengeCount)
	}
}

func TestBruteHTTPHTTPSParamUsesTLS(t *testing.T) {
	httpAuthCache = sync.Map{}

	const (
		validUser = "admin"
		validPass = "secret"
	)

	var sawTLS bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTLS = r.TLS != nil
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(validUser+":"+validPass))
		if r.Header.Get("Authorization") == expected {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="tls"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{
		"auth":  "BASIC",
		"https": "true",
	})
	if !result.AuthSuccess {
		t.Fatalf("expected HTTPS Basic auth success with params[\"https\"], got %+v", result)
	}
	if !sawTLS {
		t.Fatal("expected request to reach TLS test server over HTTPS")
	}
}

func TestBruteHTTPExplicitDigestProbeSendsCustomHeader(t *testing.T) {
	httpAuthCache = sync.Map{}

	const (
		validUser     = "admin"
		validPass     = "secret"
		realm         = "header-gated-digest"
		requiredName  = "X-Digest-Gate"
		requiredValue = "open"
	)

	var challengeCount int
	var nonce string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requiredName) != requiredValue {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			challengeCount++
			nonce = fmt.Sprintf("header-nonce-%d", challengeCount)
			w.Header().Set("WWW-Authenticate", digestChallenge(realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(auth, "Digest ") && validDigestAuth(r, auth, validUser, validPass, realm, nonce) {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("WWW-Authenticate", digestChallenge(realm, nonce))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port := parseHostPort(t, server.URL)
	cm := newTestCM()

	result := BruteHTTP(host, port, validUser, validPass, 5*time.Second, cm, ModuleParams{
		"auth":          "DIGEST",
		"custom-header": requiredName + ": " + requiredValue,
	})
	if !result.ConnectionSuccess {
		t.Fatalf("expected connection success for explicit Digest custom-header probe, got %+v", result)
	}
	if !result.AuthSuccess {
		t.Fatalf("explicit Digest should authenticate when its challenge probe requires params[\"custom-header\"], got %+v", result)
	}
	if challengeCount != 1 {
		t.Fatalf("expected one custom-header-gated Digest challenge, got %d", challengeCount)
	}
}

func digestChallenge(realm, nonce string) string {
	return fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, realm, nonce)
}

func validDigestAuth(r *http.Request, auth, user, password, realm, nonce string) bool {
	if nonce == "" {
		return false
	}

	username := parseDigestField(auth, "username")
	respHash := parseDigestField(auth, "response")
	uri := parseDigestField(auth, "uri")
	nc := parseDigestField(auth, "nc")
	cnonce := parseDigestField(auth, "cnonce")

	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(username+":"+realm+":"+password)))
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(r.Method+":"+uri)))
	expected := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+nonce+":"+nc+":"+cnonce+":auth:"+ha2)))

	return username == user && parseDigestField(auth, "nonce") == nonce && respHash == expected
}
