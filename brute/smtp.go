package brute

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
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

func BruteSMTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	auth := PlainAuth("", user, password, host)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		authSuccess bool
		connSuccess bool
	}
	done := make(chan result, 1)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}

	go func() {
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{false, false}
			return
		}

		smtpClient, err := smtp.NewClient(conn, host)
		if err != nil {
			done <- result{false, true}
			return
		}
		defer smtpClient.Quit() //nolint:errcheck

		if err := smtpClient.Auth(auth); err == nil {
			done <- result{true, true}
			return
		}

		// If plain auth failed, try STARTTLS if supported
		if ok, _ := smtpClient.Extension("STARTTLS"); ok {
			config := &tls.Config{ServerName: host, InsecureSkipVerify: true}
			if err := smtpClient.StartTLS(config); err == nil {
				if err := smtpClient.Auth(auth); err == nil {
					done <- result{true, true}
					return
				}
			}
		}

		done <- result{false, true}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return r.authSuccess, r.connSuccess
		default:
			return false, false
		}
	case r := <-done:
		return r.authSuccess, r.connSuccess
	}
}

func init() { Register("smtp", BruteSMTP) }
