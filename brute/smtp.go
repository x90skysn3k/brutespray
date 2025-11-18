package brute

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteSMTP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	auth := smtp.PlainAuth("", user, password, host)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	// Do not close here, we pass it to NewClient

	smtpClient, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return false, true
	}

	defer func() {
		if err := smtpClient.Quit(); err != nil {
			// Connection might be closed by Quit
			conn.Close()
		}
	}()

	// Note: original code had a separate TLS dialer path which bypassed cm.
	// We should try to use cm for TLS too if possible, or at least use the cm for the base connection.
	// The original code logic was bit complex with a separate TLS attempt.
	// For simplicity and correctness with cm, we stick to the first attempt using cm.
	// If strict TLS is needed, we should wrap the cm connection.

	// For now, we preserve the original logic structure but use cm where possible.
	// The original code attempted plain connection, then a separate TLS connection.

	if err := smtpClient.Auth(auth); err == nil {
		return true, false
	}

	// If plain auth failed, try TLS (STARTTLS or direct)
	// The original code created a NEW tls connection.
	// We can try to STARTTLS on the existing client if supported.
	if ok, _ := smtpClient.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: host, InsecureSkipVerify: true}
		if err := smtpClient.StartTLS(config); err == nil {
			if err := smtpClient.Auth(auth); err == nil {
				return true, false
			}
		}
	}

	return false, true
}
