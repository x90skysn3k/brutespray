package brute

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
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
//	csrf         — CSRF token hidden field name (enables GET-before-POST)
//	form-url     — URL to GET for CSRF token (default: same as url)
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

	// Replace credential placeholders in body.
	// URL-encode credentials for form-urlencoded content types to prevent
	// body corruption when passwords contain & or = characters.
	effectiveUser := user
	effectivePass := password
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		effectiveUser = url.QueryEscape(user)
		effectivePass = url.QueryEscape(password)
	}

	// Base64-encoded credential variants
	userB64 := base64.StdEncoding.EncodeToString([]byte(user))
	passB64 := base64.StdEncoding.EncodeToString([]byte(password))

	body := bodyTemplate
	body = strings.ReplaceAll(body, "%U64", userB64)
	body = strings.ReplaceAll(body, "%W64", passB64)
	body = strings.ReplaceAll(body, "%U", effectiveUser)
	body = strings.ReplaceAll(body, "%W", effectivePass)

	// Build HTTP client with cookie jar
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		Jar:       jar,
	}
	if !followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// CSRF token extraction
	csrfField := params["csrf"]
	if csrfField != "" {
		formURL := params["form-url"]
		if formURL == "" {
			formURL = urlPath
		}
		csrfURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, formURL)

		csrfReq, err := http.NewRequest("GET", csrfURL, nil)
		if err == nil {
			csrfReq.Header.Set("User-Agent", ua)
			csrfResp, err := httpClient.Do(csrfReq)
			if err == nil {
				csrfBody, _ := io.ReadAll(io.LimitReader(csrfResp.Body, 1<<20))
				csrfResp.Body.Close()

				// Extract CSRF token value from hidden input field
				pattern := fmt.Sprintf(`<input[^>]*name="%s"[^>]*value="([^"]*)"`, regexp.QuoteMeta(csrfField))
				re := regexp.MustCompile(pattern)
				if matches := re.FindSubmatch(csrfBody); len(matches) > 1 {
					csrfToken := string(matches[1])
					body = strings.ReplaceAll(body, "%C", csrfToken)
				}
				// Also try value before name order
				if strings.Contains(body, "%C") {
					pattern2 := fmt.Sprintf(`<input[^>]*value="([^"]*)"[^>]*name="%s"`, regexp.QuoteMeta(csrfField))
					re2 := regexp.MustCompile(pattern2)
					if matches := re2.FindSubmatch(csrfBody); len(matches) > 1 {
						csrfToken := string(matches[1])
						body = strings.ReplaceAll(body, "%C", csrfToken)
					}
				}
			}
		}
		// If CSRF extraction fails, proceed without it (don't fail)
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

	// Custom cookie (in addition to cookie jar)
	if cookie := params["cookie"]; cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	// Execute request
	resp, err := httpClient.Do(req)
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
