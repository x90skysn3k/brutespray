package brute

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

type plainAuth struct {
	identity, username, password string
	host                         string
}

func PlainAuth(identity, username, password, host string) smtp.Auth {
	return &plainAuth{identity, username, password, host}
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

// loginAuth implements AUTH LOGIN (multi-step base64 exchange)
type loginAuth struct {
	username, password string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(base64.StdEncoding.EncodeToString([]byte(a.username))), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	challenge := strings.ToLower(string(fromServer))
	if strings.Contains(challenge, "password") {
		return []byte(base64.StdEncoding.EncodeToString([]byte(a.password))), nil
	}
	if strings.Contains(challenge, "username") {
		return []byte(base64.StdEncoding.EncodeToString([]byte(a.username))), nil
	}
	return nil, fmt.Errorf("unexpected LOGIN challenge: %s", fromServer)
}

func BruteSMTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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

		smtpClient, err := smtp.NewClient(conn, host)
		if err != nil {
			done <- result{false, true, ""}
			return
		}
		defer smtpClient.Quit() //nolint:errcheck

		// Send EHLO to discover capabilities
		ehloHost := params["ehlo"]
		if ehloHost == "" {
			ehloHost = "brutespray"
		}
		_ = smtpClient.Hello(ehloHost)

		// Detect available auth methods
		authMethods := ""
		if ok, methods := smtpClient.Extension("AUTH"); ok {
			authMethods = methods
		}

		// Build banner from EHLO capabilities
		banner := ""
		if authMethods != "" {
			banner = "AUTH: " + authMethods
		}

		// Try STARTTLS if available (before auth)
		if ok, _ := smtpClient.Extension("STARTTLS"); ok {
			config := &tls.Config{ServerName: host, InsecureSkipVerify: true}
			if err := smtpClient.StartTLS(config); err == nil {
				// Re-detect auth methods after STARTTLS
				if ok, methods := smtpClient.Extension("AUTH"); ok {
					authMethods = methods
					banner = "AUTH: " + authMethods + " (TLS)"
				}
			}
		}

		// Determine which auth method to use
		requestedAuth := strings.ToUpper(params["auth"])

		tryAuth := func(a smtp.Auth) bool {
			return smtpClient.Auth(a) == nil
		}

		switch requestedAuth {
		case "PLAIN":
			if tryAuth(PlainAuth("", user, password, host)) {
				done <- result{true, true, banner}
				return
			}
		case "LOGIN":
			if tryAuth(&loginAuth{user, password}) {
				done <- result{true, true, banner}
				return
			}
		default:
			// AUTO: try methods in order based on server capabilities
			methods := strings.ToUpper(authMethods)

			// Try PLAIN first (most common)
			if strings.Contains(methods, "PLAIN") || methods == "" {
				if tryAuth(PlainAuth("", user, password, host)) {
					done <- result{true, true, banner}
					return
				}
			}

			// Try LOGIN
			if strings.Contains(methods, "LOGIN") {
				if tryAuth(&loginAuth{user, password}) {
					done <- result{true, true, banner}
					return
				}
			}

			// If no methods matched or all failed, try PLAIN as fallback
			if !strings.Contains(methods, "PLAIN") && methods != "" {
				if tryAuth(PlainAuth("", user, password, host)) {
					done <- result{true, true, banner}
					return
				}
			}
		}

		done <- result{false, true, banner}
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

func init() { Register("smtp", BruteSMTP) }
