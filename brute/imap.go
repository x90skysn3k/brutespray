package brute

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		authSuccess bool
		connSuccess bool
		banner      string
	}
	done := make(chan result, 1)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{false, false, ""}
			return
		}

		c, err := client.New(conn)
		if err != nil {
			done <- result{false, true, ""}
			return
		}
		defer func() {
			_ = c.Logout()
		}()

		// Capture capabilities as banner
		banner := ""
		if caps, err := c.Capability(); err == nil && len(caps) > 0 {
			names := make([]string, 0, len(caps))
			for k := range caps {
				names = append(names, k)
			}
			sort.Strings(names)
			banner = strings.Join(names, " ")
		}

		// Attempt STARTTLS if supported
		if ok, _ := c.SupportStartTLS(); ok {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			}
			if err := c.StartTLS(tlsConfig); err == nil {
				if banner != "" {
					banner += " (TLS)"
				}
			}
		}

		// Determine auth method from params
		authMethod := strings.ToUpper(params["auth"])

		switch authMethod {
		case "PLAIN":
			err = c.Authenticate(sasl.NewPlainClient("", user, password))
		default: // LOGIN (default)
			err = c.Login(user, password)
		}

		if err != nil {
			done <- result{false, true, banner}
			return
		}

		done <- result{true, true, banner}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess, Banner: r.banner}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case r := <-done:
		return &BruteResult{AuthSuccess: r.authSuccess, ConnectionSuccess: r.connSuccess, Banner: r.banner}
	}
}

func init() { Register("imap", BruteIMAP) }
