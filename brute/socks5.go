package brute

import (
	"context"
	"fmt"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteSocks5 brute-forces SOCKS5 proxy authentication per RFC 1928/1929.
func BruteSocks5(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := cm.Dial("tcp", addr)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer conn.Close()

		// Propagate context cancellation
		go func() {
			<-ctx.Done()
			_ = conn.SetDeadline(time.Now())
		}()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		// Step 1: Greeting — request username/password auth (0x02) and no-auth (0x00)
		_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}

		greeting := make([]byte, 2)
		n, err := conn.Read(greeting)
		if err != nil || n < 2 {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}

		if greeting[0] != 0x05 {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
				Error: fmt.Errorf("not a SOCKS5 server")}
		}

		switch greeting[1] {
		case 0x00:
			// No authentication required — server doesn't need credentials
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true,
				Banner: "no-auth-required"}
		case 0x02:
			// Username/password authentication selected — proceed
		case 0xFF:
			// No acceptable methods
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("no acceptable auth methods")}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("unsupported auth method: 0x%02x", greeting[1])}
		}

		// Step 2: Username/password auth (RFC 1929)
		// Format: [0x01, ulen, user..., plen, pass...]
		uBytes := []byte(user)
		pBytes := []byte(password)
		if len(uBytes) > 255 || len(pBytes) > 255 {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("credentials too long for SOCKS5")}
		}

		authReq := make([]byte, 0, 3+len(uBytes)+len(pBytes))
		authReq = append(authReq, 0x01, byte(len(uBytes)))
		authReq = append(authReq, uBytes...)
		authReq = append(authReq, byte(len(pBytes)))
		authReq = append(authReq, pBytes...)

		_, err = conn.Write(authReq)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		authResp := make([]byte, 2)
		n, err = conn.Read(authResp)
		if err != nil || n < 2 {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		if authResp[1] != 0x00 {
			// Auth failed
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}

		// Auth succeeded — verify proxy is functional with a CONNECT request.
		// Some misconfigured proxies accept any credentials but can't proxy.
		// CONNECT to 0.0.0.1:80 (non-routable): any reply proves proxy works.
		connectReq := []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50}
		_, err = conn.Write(connectReq)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Banner: "auth-accepted-but-proxy-nonfunctional"}
		}
		verifyResp := make([]byte, 10)
		n, err = conn.Read(verifyResp)
		if err != nil || n < 2 {
			// Proxy accepted auth but can't actually proxy → false positive
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Banner: "auth-accepted-but-proxy-nonfunctional"}
		}
		// Any reply (even connection refused = 0x05) proves proxy is real
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("socks5-auth", BruteSocks5) }
