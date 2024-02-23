package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

func BruteSMTP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	auth := smtp.PlainAuth("", user, password, host)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	smtpClient, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, true
	}

	defer func() {
		if err := smtpClient.Quit(); err != nil {
			_ = err
			//fmt.Printf("Failed to send QUIT command: %v\n", err)
		}
	}()

	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: timeout,
		},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		},
	}

	tlsConn, err := tlsDialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err == nil {
		smtpClient, err = smtp.NewClient(tlsConn, host)
		if err != nil {
			return false, true
		}
		defer func() {
			if err := smtpClient.Quit(); err != nil {
				_ = err
				//fmt.Printf("Failed to send QUIT command: %v\n", err)
			}
		}()
		if err := smtpClient.Auth(auth); err == nil {
			return true, true
		}
	}
	if err := smtpClient.Auth(auth); err == nil {
		return true, false
	}

	return false, true
}
