package brute

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

func BruteSSH(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ssh.Client
		err    error
	}
	done := make(chan result)

	var err error
	var conn net.Conn

	if socks5 != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5, nil, nil)
		if err != nil {
			return false, false
		}
		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	}

	if err != nil {
		return false, false
	}

	go func() {
		clientConn, clientChannels, clientRequests, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), config)
		if err != nil {
			done <- result{nil, err}
			return
		}
		client := ssh.NewClient(clientConn, clientChannels, clientRequests)
		done <- result{client, nil}
	}()

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.err != nil {
			return false, true
		}
		result.client.Close()
		return true, true
	}
}
