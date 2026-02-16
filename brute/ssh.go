package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
	"golang.org/x/crypto/ssh"
)

func BruteSSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
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
	done := make(chan result, 1)

	var err error
	var conn net.Conn

	conn, err = cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	defer conn.Close()

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
		// Timeout fired, but the auth goroutine may have just succeeded.
		// Prefer any available result over reporting timeout (avoids missing
		// valid credentials under high concurrency when both channels are ready).
		select {
		case result := <-done:
			if result.err != nil {
				return false, true
			}
			result.client.Close()
			return true, true
		default:
			return false, false
		}
	case result := <-done:
		if result.err != nil {
			return false, true
		}
		result.client.Close()
		return true, true
	}
}
