package brute

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteHTTPForm brute-forces HTML login forms using configurable POST/GET
// requests with credential placeholders.
//
// Required params:
//
//	url   — login form path (e.g., /login)
//	body  — POST body with %U/%W placeholders (e.g., user=%U&pass=%W)
//	fail  — failure string in response body (e.g., "Invalid credentials")
//
// Optional params:
//
//	success      — success string (alternative to fail matching)
//	follow       — follow redirects (true/false, default false)
//	cookie       — custom cookie to send
//	content-type — default application/x-www-form-urlencoded
//	method       — POST (default) or GET
//	user-agent   — custom User-Agent
func BruteHTTPForm(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	scheme := "http"
	if params["https"] == "true" {
		scheme = "https"
	}

	// Target path
	urlPath := params["url"]
	if urlPath == "" {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
			Error: fmt.Errorf("http-form module requires -m url:/path parameter")}
	}

	bodyTemplate := params["body"]
	failString := params["fail"]
	successString := params["success"]

	if bodyTemplate == "" && failString == "" && successString == "" {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
			Error: fmt.Errorf("http-form module requires -m body:TEMPLATE and -m fail:STRING or -m success:STRING")}
	}

	// HTTP method
	method := strings.ToUpper(params["method"])
	if method == "" {
		method = "POST"
	}

	// Content-Type
	contentType := params["content-type"]
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}

	// User-Agent
	ua := params["user-agent"]
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	// Follow redirects
	followRedirects := strings.ToLower(params["follow"]) == "true"

	// Build URL
	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, urlPath)

	// Replace credential placeholders in body
	body := bodyTemplate
	body = strings.ReplaceAll(body, "%U", user)
	body = strings.ReplaceAll(body, "%W", password)

	// Build HTTP client
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Build request
	var req *http.Request
	var err error
	if method == "GET" {
		// For GET, append body as query params
		if body != "" {
			if strings.Contains(targetURL, "?") {
				targetURL += "&" + body
			} else {
				targetURL += "?" + body
			}
		}
		req, err = http.NewRequest("GET", targetURL, nil)
	} else {
		req, err = http.NewRequest(method, targetURL, strings.NewReader(body))
	}
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	if method != "GET" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", ua)

	// Custom cookie
	if cookie := params["cookie"]; cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Read response body (limit to 1MB to avoid memory issues)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}
	responseBody := string(bodyBytes)

	banner := resp.Header.Get("Server")

	// Determine success/failure
	if successString != "" {
		// Success mode: look for success string in response
		if strings.Contains(responseBody, successString) {
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
	}

	if failString != "" {
		// Fail mode: look for failure string in response — absence means success
		if strings.Contains(responseBody, failString) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
		}
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
	}

	// Fallback: use HTTP status code
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
	}
	return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
}

func init() {
	Register("http-form", BruteHTTPForm)
	Register("https-form", BruteHTTPForm)
}
