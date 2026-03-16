package brute

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/go-vnc"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: password,
			},
		},
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		authSuccess bool
		connSuccess bool
		err         error
	}
	done := make(chan result, 1)

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		client, err := vnc.Client(conn, config)
		if err != nil {
			done <- result{false, true, err}
			return
		}
		client.Close()
		done <- result{true, true, nil}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return vncHandleResult(r.authSuccess, r.connSuccess, r.err, params)
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		return vncHandleResult(r.authSuccess, r.connSuccess, r.err, params)
	}
}

// vncHandleResult processes a VNC attempt result and detects anti-brute-force measures
func vncHandleResult(authSuccess, connSuccess bool, err error, params ModuleParams) *BruteResult {
	br := &BruteResult{AuthSuccess: authSuccess, ConnectionSuccess: connSuccess, Error: err}

	if !connSuccess && err != nil {
		errStr := strings.ToLower(err.Error())
		// Detect VNC anti-brute-force: "too many" attempts, blacklisted, etc.
		if strings.Contains(errStr, "too many") ||
			strings.Contains(errStr, "blacklist") ||
			strings.Contains(errStr, "security type") ||
			strings.Contains(errStr, "no matching security") {
			// Signal retry delay for anti-brute detection
			maxSleep := 60
			if ms := params["maxsleep"]; ms != "" {
				if v, err := strconv.Atoi(ms); err == nil && v > 0 {
					maxSleep = v
				}
			}
			br.RetryDelay = time.Duration(maxSleep) * time.Second
			br.Banner = "VNC anti-brute-force detected"
		}
	}

	return br
}

func init() { Register("vnc", BruteVNC) }
