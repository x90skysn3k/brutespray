package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteSMB(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string, domain string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		session *smb2.Session
		conn    net.Conn
		err     error
	}
	done := make(chan result)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		//fmt.Println("Failed to create connection manager:", err)
		return false, false
	}

	go func() {
		//fmt.Println("Attempting to connect to:", host, "port:", port)
		conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			//fmt.Println("Connection error:", err)
			done <- result{nil, nil, err}
			return
		}

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			//fmt.Println("Error setting connection deadline:", err)
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

		//fmt.Println("Dialing SMB connection...")
		session, err := d.Dial(conn)
		done <- result{session, conn, err}
	}()

	select {
	case <-timer.C:
		//fmt.Println("Timeout reached")
		return false, false
	case result := <-done:
		if result.err != nil {
			//fmt.Println("SMB login failed:", result.err)
			if result.conn != nil {
				result.conn.Close()
			}
			return false, true
		}

		//fmt.Println("Listing share names to verify login...")
		_, err := result.session.ListSharenames()
		if err != nil {
			//fmt.Println("Failed to list share names:", err)
			result.conn.Close()
			return false, true
		}

		//fmt.Println("Login successful. Shares:", shares)
		result.conn.Close()
		return true, true
	}
}
