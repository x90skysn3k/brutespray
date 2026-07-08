package brute

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// httpAuthCache caches the detected auth type per request scope to avoid cross-path auth reuse.
var httpAuthCache sync.Map

type httpAuthCacheKey struct {
	Scheme       string
	Host         string
	Port         int
	Method       string
	Path         string
	CustomHeader string
}

type httpAuthCacheEntry struct {
	AuthType               string
	UnauthenticatedSuccess bool
	UnauthenticatedBanner  string
}

func BruteHTTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	scheme := "http"
	if params["https"] == "true" {
		scheme = "https"
	}

	// Target path
	dir := params["dir"]
	if dir == "" {
		dir = "/"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, dir)

	// HTTP method
	method := strings.ToUpper(params["method"])
	if method == "" {
		method = "GET"
	}

	// User-Agent
	ua := params["user-agent"]
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	// Build HTTP client
	var client *http.Client
	if cm.SharedHTTPClient != nil {
		client = cm.SharedHTTPClient
	} else {
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

	// Determine auth method
	requestedAuth := strings.ToUpper(params["auth"])

	// Auto-detect: probe for WWW-Authenticate header
	detectedAuth := requestedAuth
	var wwwAuthHeader string
	var autoDetectUnauthenticatedSuccess bool
	var autoDetectUnauthenticatedBanner string

	switch detectedAuth {
	case "", "AUTO":
		cacheKey := httpAuthCacheKey{
			Scheme:       scheme,
			Host:         host,
			Port:         port,
			Method:       method,
			Path:         dir,
			CustomHeader: params["custom-header"],
		}
		if cached, ok := httpAuthCache.Load(cacheKey); ok {
			switch cacheEntry := cached.(type) {
			case httpAuthCacheEntry:
				detectedAuth = cacheEntry.AuthType
				autoDetectUnauthenticatedSuccess = cacheEntry.UnauthenticatedSuccess
				autoDetectUnauthenticatedBanner = cacheEntry.UnauthenticatedBanner
			case string:
				detectedAuth = cacheEntry
			}
			if detectedAuth == "DIGEST" {
				probe := probeHTTPAuth(client, method, url, ua, params)
				if probe.Result != nil {
					return probe.Result
				}
				detectedAuth = probe.AuthType
				wwwAuthHeader = probe.WWWAuthHeader
				autoDetectUnauthenticatedSuccess = probe.UnauthenticatedSuccess
				autoDetectUnauthenticatedBanner = probe.UnauthenticatedBanner
				httpAuthCache.Store(cacheKey, httpAuthCacheEntry{
					AuthType:               detectedAuth,
					UnauthenticatedSuccess: autoDetectUnauthenticatedSuccess,
					UnauthenticatedBanner:  autoDetectUnauthenticatedBanner,
				})
			}
		} else {
			probe := probeHTTPAuth(client, method, url, ua, params)
			if probe.Result != nil {
				return probe.Result
			}
			detectedAuth = probe.AuthType
			wwwAuthHeader = probe.WWWAuthHeader
			autoDetectUnauthenticatedSuccess = probe.UnauthenticatedSuccess
			autoDetectUnauthenticatedBanner = probe.UnauthenticatedBanner
			httpAuthCache.Store(cacheKey, httpAuthCacheEntry{
				AuthType:               detectedAuth,
				UnauthenticatedSuccess: autoDetectUnauthenticatedSuccess,
				UnauthenticatedBanner:  autoDetectUnauthenticatedBanner,
			})
		}
	case "BASIC":
		probeMethod := basicProbeMethod(method)
		probe := probeHTTPAuth(client, probeMethod, url, ua, params)
		if probe.Result != nil {
			if probe.Result.Error != nil || !probe.Result.ConnectionSuccess {
				return probe.Result
			}
			if strings.EqualFold(probeMethod, method) {
				autoDetectUnauthenticatedSuccess = true
				autoDetectUnauthenticatedBanner = probe.Result.Banner
			}
		} else if strings.EqualFold(probeMethod, method) {
			autoDetectUnauthenticatedSuccess = probe.UnauthenticatedSuccess
			autoDetectUnauthenticatedBanner = probe.UnauthenticatedBanner
		}
	}

	// Build the auth request
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	req.Header.Set("User-Agent", ua)
	applyHTTPCustomHeader(req, params)

	var result *BruteResult
	switch detectedAuth {
	case "NTLM":
		result = bruteHTTPNTLM(client, req, user, password, params["domain"], url, method, ua, params)
	case "DIGEST":
		result = bruteHTTPDigest(client, req, user, password, wwwAuthHeader, url, method, ua, params)
	default: // BASIC
		auth := user + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", basicAuth)

		resp, err := client.Do(req)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		result = httpResult(resp)
	}

	if autoDetectUnauthenticatedSuccess {
		if result.Banner == "" {
			result.Banner = autoDetectUnauthenticatedBanner
		} else if autoDetectUnauthenticatedBanner != "" && !strings.Contains(result.Banner, autoDetectUnauthenticatedBanner) {
			result.Banner += "; " + autoDetectUnauthenticatedBanner
		}
		if result.AuthSuccess {
			result.AuthSuccess = false
		}
	}
	return result
}

type httpAuthProbe struct {
	AuthType               string
	WWWAuthHeader          string
	Result                 *BruteResult
	UnauthenticatedSuccess bool
	UnauthenticatedBanner  string
}

func probeHTTPAuth(client *http.Client, method, url, ua string, params ModuleParams) httpAuthProbe {
	probeReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		return httpAuthProbe{Result: &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}}
	}
	probeReq.Header.Set("User-Agent", ua)
	applyHTTPCustomHeader(probeReq, params)

	probeResp, err := client.Do(probeReq)
	if err != nil {
		return httpAuthProbe{Result: &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}}
	}
	_, _ = io.Copy(io.Discard, probeResp.Body)
	_ = probeResp.Body.Close()

	wwwAuthHeader := probeResp.Header.Get("WWW-Authenticate")
	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 && wwwAuthHeader == "" {
		return httpAuthProbe{Result: &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: httpBanner(probeResp)}}
	}

	probeBanner := httpBanner(probeResp)
	return httpAuthProbe{
		AuthType:               detectHTTPAuthType(wwwAuthHeader),
		WWWAuthHeader:          wwwAuthHeader,
		UnauthenticatedSuccess: probeResp.StatusCode >= 200 && probeResp.StatusCode < 300,
		UnauthenticatedBanner:  probeBanner,
	}
}

func detectHTTPAuthType(wwwAuthHeader string) string {
	upperAuth := strings.ToUpper(wwwAuthHeader)
	switch {
	case strings.Contains(upperAuth, "NTLM"):
		return "NTLM"
	case strings.Contains(upperAuth, "DIGEST"):
		return "DIGEST"
	default:
		return "BASIC"
	}
}

func basicProbeMethod(method string) string {
	if isHTTPSafeMethod(method) {
		return method
	}
	return "GET"
}

func isHTTPSafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

func applyHTTPCustomHeader(req *http.Request, params ModuleParams) {
	if h := params["custom-header"]; h != "" {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

// bruteHTTPNTLM performs NTLM authentication via HTTP
func bruteHTTPNTLM(client *http.Client, req *http.Request, user, password, domain, url, method, ua string, params ModuleParams) *BruteResult {
	// NTLM negotiate message
	negotiateMsg, err := ntlmssp.NewNegotiateMessage(domain, "")
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}

	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiateMsg))

	resp, err := client.Do(req)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Parse challenge from response
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToUpper(authHeader), "NTLM ") {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
			Error: fmt.Errorf("no NTLM challenge in response")}
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "NTLM "))
	if err != nil {
		// Try case-insensitive trim
		challengeBytes, err = base64.StdEncoding.DecodeString(authHeader[5:])
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
	}

	// Generate authenticate message
	authenticateMsg, err := ntlmssp.NewAuthenticateMessage(challengeBytes, user, password, nil)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}

	// Send authenticate
	authReq, _ := http.NewRequest(method, url, nil)
	authReq.Header.Set("User-Agent", ua)
	authReq.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticateMsg))
	applyHTTPCustomHeader(authReq, params)

	authResp, err := client.Do(authReq)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, authResp.Body)
		_ = authResp.Body.Close()
	}()

	return httpResult(authResp)
}

// bruteHTTPDigest performs Digest authentication per RFC 2617
func bruteHTTPDigest(client *http.Client, req *http.Request, user, password, wwwAuth, url, method, ua string, params ModuleParams) *BruteResult {
	// If we don't have the WWW-Authenticate header yet, do a probe
	if wwwAuth == "" {
		probeReq, err := http.NewRequest(method, url, nil)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		probeReq.Header.Set("User-Agent", ua)
		applyHTTPCustomHeader(probeReq, params)
		probeResp, err := client.Do(probeReq)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		_, _ = io.Copy(io.Discard, probeResp.Body)
		_ = probeResp.Body.Close()
		wwwAuth = probeResp.Header.Get("WWW-Authenticate")
	}

	// Parse Digest challenge
	realm := parseDigestField(wwwAuth, "realm")
	nonce := parseDigestField(wwwAuth, "nonce")
	qop := parseDigestField(wwwAuth, "qop")
	opaque := parseDigestField(wwwAuth, "opaque")

	if nonce == "" {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
			Error: fmt.Errorf("missing nonce in Digest challenge")}
	}

	// Compute Digest response per RFC 2617
	ha1 := md5hex(user + ":" + realm + ":" + password)

	// Extract URI path
	uri := "/"
	if params["dir"] != "" {
		uri = params["dir"]
	}
	ha2 := md5hex(method + ":" + uri)

	nc := "00000001"
	cnonce := fmt.Sprintf("%08x", rand.Int31())

	var response string
	if strings.Contains(qop, "auth") {
		response = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	} else {
		response = md5hex(ha1 + ":" + nonce + ":" + ha2)
	}

	// Build Authorization header
	authHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		user, realm, nonce, uri, response)
	if qop != "" {
		authHeader += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
	}
	if opaque != "" {
		authHeader += fmt.Sprintf(`, opaque="%s"`, opaque)
	}

	req.Header.Set("Authorization", authHeader)

	resp, err := client.Do(req)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return httpResult(resp)
}

func httpBanner(resp *http.Response) string {
	banner := resp.Header.Get("Server")
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		if banner != "" {
			banner += "; "
		}
		banner += "Auth: " + wwwAuth
	}
	return banner
}

// httpResult converts an HTTP response to a BruteResult
func httpResult(resp *http.Response) *BruteResult {
	banner := httpBanner(resp)

	switch resp.StatusCode {
	case 200, 201, 202, 204:
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
	default:
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
	}
}

// parseDigestField extracts a named field from a Digest WWW-Authenticate header
func parseDigestField(header, field string) string {
	lower := strings.ToLower(header)
	key := strings.ToLower(field) + "="
	idx := strings.Index(lower, key)
	if idx < 0 {
		return ""
	}
	val := header[idx+len(key):]
	if len(val) > 0 && val[0] == '"' {
		val = val[1:]
		if before, _, ok := strings.Cut(val, "\""); ok {
			return before
		}
		return val
	}
	end := strings.IndexAny(val, ", ")
	if end >= 0 {
		return val[:end]
	}
	return val
}

// md5hex computes MD5 and returns hex string
func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}

func init() {
	Register("http", BruteHTTP)
	Register("https", BruteHTTP)
}
