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

func BruteHTTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, useHTTPS bool) *BruteResult {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)

	// Use shared HTTP client if available for connection pooling
	var client *http.Client
	if cm.SharedHTTPClient != nil {
		client = cm.SharedHTTPClient
	} else {
		// Fallback for legacy/testing without initialized CM
		transport := &http.Transport{
			Dial:                  cm.DialFunc,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
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
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	switch resp.StatusCode {
	case 200, 201, 202, 204:
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	case 301, 302, 303, 307, 308:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	case 401:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	case 403:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	case 404, 405:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	case 500, 502, 503, 504:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	default:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	}
}

func init() {
	RegisterHTTP("http", BruteHTTP)
	RegisterHTTP("https", BruteHTTP)
}
