package brute

import (
	"context"
	"fmt"
	"net/textproto"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteSMTPVRFY performs SMTP user enumeration via VRFY, EXPN, or RCPT TO.
// The username field is the address to verify; password is ignored.
func BruteSMTPVRFY(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		tc := textproto.NewConn(conn)
		defer tc.Close()

		// Read greeting
		code, greeting, err := tc.ReadResponse(220)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}
		_ = code

		banner := greeting

		// Send EHLO
		if err := tc.PrintfLine("EHLO brutespray"); err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
		}
		_, _, _ = tc.ReadResponse(250)

		verb := strings.ToUpper(params["verb"])
		if verb == "" {
			verb = "VRFY"
		}

		switch verb {
		case "VRFY":
			if err := tc.PrintfLine("VRFY %s", sanitizeCred(user)); err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			// 250, 251, 252 = user exists
			if code == 250 || code == 251 || code == 252 {
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}

		case "EXPN":
			if err := tc.PrintfLine("EXPN %s", sanitizeCred(user)); err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			if code == 250 || code == 251 || code == 252 {
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}

		case "RCPT":
			// MAIL FROM
			if err := tc.PrintfLine("MAIL FROM:<>"); err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}

			// Build RCPT address
			addr := user
			if domain := params["domain"]; domain != "" && !strings.Contains(user, "@") {
				addr = user + "@" + domain
			}

			if err := tc.PrintfLine("RCPT TO:<%s>", sanitizeCred(addr)); err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			code, _, err = tc.ReadResponse(0)
			if err != nil && code == 0 {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
			}
			if code == 250 || code == 251 || code == 252 {
				return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}

		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Banner: banner}
		}
	})
}

func init() { Register("smtp-vrfy", BruteSMTPVRFY) }
