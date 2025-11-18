package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteSMB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, domain string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		session *smb2.Session
		conn    net.Conn
		err     error
	}
	done := make(chan result, 1)

	go func() {
		conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{nil, nil, err}
			return
		}

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{nil, conn, err}
			return
		}

		d := &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     user,
				Password: password,
				Domain:   domain,
			},
		}

		session, err := d.Dial(conn)
		done <- result{session, conn, err}
	}()

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.err != nil {
			if result.conn != nil {
				result.conn.Close()
			}
			return false, true
		}

		_, err := result.session.ListSharenames()
		if err != nil {
			result.conn.Close()
			return false, true
		}

		result.conn.Close()
		return true, true
	}
}
