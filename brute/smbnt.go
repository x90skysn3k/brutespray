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

	handleResult := func(r result) (bool, bool) {
		if r.err != nil {
			if r.conn != nil {
				r.conn.Close()
			}
			return false, true
		}
		_, err := r.session.ListSharenames()
		_ = r.session.Logoff()
		r.conn.Close()
		if err != nil {
			return false, true
		}
		return true, true
	}

	select {
	case <-timer.C:
		select {
		case r := <-done:
			return handleResult(r)
		default:
			return false, false
		}
	case r := <-done:
		return handleResult(r)
	}
}
