package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteLDAP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var l *ldap.Conn
	if port == 636 {
		// LDAPS
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		l = ldap.NewConn(tlsConn, true)
	} else {
		l = ldap.NewConn(conn, false)
	}
	l.Start()
	defer l.Close()

	err = l.Bind(user, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		// Check if it's a network error
		if _, ok := err.(*net.OpError); ok {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}

	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func init() {
	Register("ldap", BruteLDAP)
	Register("ldaps", BruteLDAP)
}
