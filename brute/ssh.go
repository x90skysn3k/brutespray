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
		// Timeout fired — force the blocked goroutine to exit by killing the
		// connection deadline so the SSH handshake fails immediately.
		_ = conn.SetDeadline(time.Now())
		// Prefer any available result over reporting timeout
		select {
		case result := <-done:
			conn.Close()
			if result.err != nil {
				return false, true
			}
			result.client.Close()
			return true, true
		default:
			conn.Close()
			return false, false
		}
	case result := <-done:
		conn.Close()
		if result.err != nil {
			return false, true
		}
		result.client.Close()
		return true, true
	}
}
