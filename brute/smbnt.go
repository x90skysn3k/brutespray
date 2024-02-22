package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func BruteSMB(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: password,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return false, true
	}
	defer s.Logoff()

	_, err = s.ListSharenames()
	if err != nil {
		return false, true
	}

	return true, true
}
