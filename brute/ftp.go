package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteFTP(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ftp.ServerConn
		err    error
	}
	done := make(chan result)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	go func() {
		conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer conn.Close()

		client, err := ftp.Dial(conn.RemoteAddr().String(), ftp.DialWithDialFunc(func(network, addr string) (net.Conn, error) { return conn, nil }))
		if err != nil {
			done <- result{nil, err}
			return
		}
		err = client.Login(user, password)
		done <- result{client, err}
	}()

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.client != nil {
			err := result.client.Quit()
			if err != nil {
				_ = err
			}
		}
		if result.err != nil {
			return false, true
		}
		return true, true
	}
}
