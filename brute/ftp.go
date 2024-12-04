package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/x90skysn3k/brutespray/modules"
	"golang.org/x/net/proxy"
)

func BruteFTP(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ftp.ServerConn
		err    error
	}
	done := make(chan result)

	var err error
	var conn net.Conn
	var service = "ftp"

	if socks5 != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5, nil, nil)
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}
		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil {
			modules.PrintSocksError(service, fmt.Sprintf("%v", err))
			return false, false
		}
	}

	go func() {
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
			}
		}
		if result.err != nil {
			return false, true
		}
		return true, true
	}
}
