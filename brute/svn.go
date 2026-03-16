package brute

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteSVN brute-forces SVN repositories using HTTP Basic authentication.
// SVN over HTTP uses WebDAV (PROPFIND or OPTIONS), but Basic auth check via
// GET/OPTIONS is sufficient for brute-forcing.
func BruteSVN(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	scheme := "http"
	if params["https"] == "true" || port == 443 {
		scheme = "https"
	}

	// Target path
	path := params["path"]
	if path == "" {
		path = "/"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)

	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	auth := user + ":" + password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	req.Header.Set("User-Agent", "SVN/1.14.0 (brutespray)")

	resp, err := client.Do(req)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	banner := resp.Header.Get("Server")
	if dav := resp.Header.Get("DAV"); dav != "" {
		if banner != "" {
			banner += "; "
		}
		banner += "DAV: " + dav
	}

	switch resp.StatusCode {
	case 200, 204, 207: // 207 = Multi-Status (WebDAV success)
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
	default:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
	}
}

func init() { Register("svn", BruteSVN) }
