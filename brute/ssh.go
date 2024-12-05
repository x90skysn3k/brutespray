package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
	"golang.org/x/crypto/ssh"
)

func BruteSSH(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
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
	var service = "ssh"

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	conn, err = cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		modules.PrintSocksError(service, fmt.Sprintf("%v", err))
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
