package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteSMTP(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	auth := smtp.PlainAuth("", user, password, host)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
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
