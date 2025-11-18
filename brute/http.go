package brute

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteHTTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	// Build the URL - handle both HTTP and HTTPS
	var url string
	if port == 443 {
		url = fmt.Sprintf("https://%s:%d", host, port)
	} else {
		url = fmt.Sprintf("http://%s:%d", host, port)
	}

	// Create HTTP client with custom transport for proxy/interface support
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: modules.InsecureTLS},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, false
	}

	// Set basic auth header
	auth := user + ":" + password
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Add("Authorization", basicAuth)

	// Set User-Agent to avoid detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		// Connection failed
		return false, false
	}
	defer func() {
		// Ensure response body is read and closed to allow connection reuse
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	// Check response status
	switch resp.StatusCode {
	case 200, 201, 202, 204, 301, 302, 303, 307, 308:
		// Success - authentication worked
		return true, true
	case 401:
		// Unauthorized - connection worked but auth failed
		return false, true
	case 403:
		// Forbidden - might be valid credentials but access denied
		return false, true
	case 404, 405:
		// Not found or method not allowed
		return false, true
	case 500, 502, 503, 504:
		// Server errors
		return false, true
	default:
		// Other status codes
		return false, true
	}
}

// BruteHTTPS is an alias for BruteHTTP since the function handles both protocols
func BruteHTTPS(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	return BruteHTTP(host, port, user, password, timeout, cm)
}
