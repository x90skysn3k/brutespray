package brute

import (
	"fmt"
	"net/textproto"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteSMTPVRFY performs SMTP user enumeration via VRFY, EXPN, or RCPT TO.
// The username field is the address to verify; password is ignored.
func BruteSMTPVRFY(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		success bool
		banner  string
	}
	done := make(chan result, 1)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(timeout))

		tc := textproto.NewConn(conn)
		defer tc.Close()

		// Read greeting
		code, greeting, err := tc.ReadResponse(220)
		if err != nil {
			done <- result{false, ""}
			return
		}
		_ = code

		banner := greeting

		// Send EHLO
		if err := tc.PrintfLine("EHLO brutespray"); err != nil {
			done <- result{false, banner}
			return
		}
		_, _, _ = tc.ReadResponse(250)

		verb := strings.ToUpper(params["verb"])
		if verb == "" {
			verb = "VRFY"
		}

		switch verb {
		case "VRFY":
			if err := tc.PrintfLine("VRFY %s", sanitizeCred(user)); err != nil {
				done <- result{false, banner}
				return
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				done <- result{false, banner}
				return
			}
			// 250, 251, 252 = user exists
			if code == 250 || code == 251 || code == 252 {
				done <- result{true, banner}
				return
			}
			done <- result{false, banner}

		case "EXPN":
			if err := tc.PrintfLine("EXPN %s", sanitizeCred(user)); err != nil {
				done <- result{false, banner}
				return
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				done <- result{false, banner}
				return
			}
			if code == 250 || code == 251 || code == 252 {
				done <- result{true, banner}
				return
			}
			done <- result{false, banner}

		case "RCPT":
			// MAIL FROM
			if err := tc.PrintfLine("MAIL FROM:<>"); err != nil {
				done <- result{false, banner}
				return
			}
			code, _, err := tc.ReadResponse(0)
			if err != nil && code == 0 {
				done <- result{false, banner}
				return
			}

			// Build RCPT address
			addr := user
			if domain := params["domain"]; domain != "" && !strings.Contains(user, "@") {
				addr = user + "@" + domain
			}

			if err := tc.PrintfLine("RCPT TO:<%s>", sanitizeCred(addr)); err != nil {
				done <- result{false, banner}
				return
			}
			code, _, err = tc.ReadResponse(0)
			if err != nil && code == 0 {
				done <- result{false, banner}
				return
			}
			if code == 250 || code == 251 || code == 252 {
				done <- result{true, banner}
				return
			}
			done <- result{false, banner}

		default:
			done <- result{false, banner}
		}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return &BruteResult{AuthSuccess: r.success, ConnectionSuccess: true, Banner: r.banner}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		return &BruteResult{AuthSuccess: r.success, ConnectionSuccess: true, Banner: r.banner}
	}
}

func init() { Register("smtp-vrfy", BruteSMTPVRFY) }
