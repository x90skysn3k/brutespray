package brute

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteLDAP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := cm.Dial("tcp", addr)
	if err != nil {
		return false, false
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
			return false, false
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
			return false, true
		}
		// Check if it's a network error
		if _, ok := err.(*net.OpError); ok {
			return false, false
		}
		return false, true
	}

	return true, true
}

func init() {
	Register("ldap", BruteLDAP)
	Register("ldaps", BruteLDAP)
}
