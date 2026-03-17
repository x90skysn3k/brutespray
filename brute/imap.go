package brute

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// cramMD5Client implements the sasl.Client interface for CRAM-MD5 authentication.
type cramMD5Client struct {
	user     string
	password string
}

func (c *cramMD5Client) Start() (string, []byte, error) {
	return "CRAM-MD5", nil, nil
}

func (c *cramMD5Client) Next(challenge []byte) ([]byte, error) {
	mac := hmac.New(md5.New, []byte(c.password))
	mac.Write(challenge)
	digest := hex.EncodeToString(mac.Sum(nil))
	return []byte(c.user + " " + digest), nil
}

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
		caps, capErr := c.Capability()
		hasCRAMMD5 := false
		if capErr == nil && len(caps) > 0 {
			names := make([]string, 0, len(caps))
			for k := range caps {
				names = append(names, k)
				if strings.EqualFold(k, "AUTH=CRAM-MD5") {
					hasCRAMMD5 = true
				}
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
				// Re-check capabilities after STARTTLS
				if newCaps, err := c.Capability(); err == nil {
					for k := range newCaps {
						if strings.EqualFold(k, "AUTH=CRAM-MD5") {
							hasCRAMMD5 = true
						}
					}
				}
			}
		}

		// Determine auth method from params
		authMethod := strings.ToUpper(params["auth"])

		switch authMethod {
		case "PLAIN":
			err = c.Authenticate(sasl.NewPlainClient("", user, password))
		case "CRAM-MD5":
			err = c.Authenticate(&cramMD5Client{user: user, password: password})
		default: // AUTO: try CRAM-MD5 if supported, fall back to LOGIN
			if hasCRAMMD5 {
				err = c.Authenticate(&cramMD5Client{user: user, password: password})
			} else {
				err = c.Login(user, password)
			}
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
