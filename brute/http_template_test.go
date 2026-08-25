package brute

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPTemplateModuleSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(readBody(t, r), `"username":"admin"`) {
			http.Error(w, "bad", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"abc"}`))
	}))
	defer server.Close()
	host, port := splitServer(t, server.URL)
	template := `id: json-login
service: http-template
transport: http
steps:
  - request:
      method: POST
      path: /login
      headers:
        content-type: application/json
      body: '{"username":"{{username}}","password":"{{password}}"}'
    matchers:
      - type: status
        status: [200]
      - type: body_contains
        body: token
`
	result := BruteHTTPTemplate(host, port, "admin", "secret", time.Second, nil, ModuleParams{"template-inline": template})
	if !result.AuthSuccess || !result.ConnectionSuccess {
		t.Fatalf("result = %+v", result)
	}
}

func TestHTTPTemplateModuleAuthFailureConnectionSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	host, port := splitServer(t, server.URL)
	template := `id: json-login
service: http-template
transport: http
steps:
  - request:
      method: POST
      path: /login
    matchers:
      - type: status
        status: [200]
`
	result := BruteHTTPTemplate(host, port, "admin", "wrong", time.Second, nil, ModuleParams{"template-inline": template})
	if result.AuthSuccess || !result.ConnectionSuccess {
		t.Fatalf("result = %+v", result)
	}
}

func TestHTTPTemplateModuleNetworkFailure(t *testing.T) {
	template := `id: json-login
service: http-template
transport: http
steps:
  - request:
      method: POST
      path: /login
    matchers:
      - type: status
        status: [200]
`
	result := BruteHTTPTemplate("127.0.0.1", 1, "admin", "secret", 100*time.Millisecond, nil, ModuleParams{"template-inline": template})
	if result.AuthSuccess || result.ConnectionSuccess {
		t.Fatalf("result = %+v", result)
	}
}

func TestHTTPTemplateModuleTemplateError(t *testing.T) {
	result := BruteHTTPTemplate("127.0.0.1", 80, "admin", "secret", time.Second, nil, nil)
	if result.AuthSuccess || result.ConnectionSuccess || result.Error == nil {
		t.Fatalf("result = %+v", result)
	}
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	data, _ := io.ReadAll(r.Body)
	return string(data)
}

func splitServer(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	hostPort := strings.TrimPrefix(rawURL, "http://")
	host, portString, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	return host, port
}
