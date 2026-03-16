package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"golang.org/x/crypto/ssh"
)

func BruteSSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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
		banner string
	}
	done := make(chan result, 1)

	var err error
	var conn net.Conn

	conn, err = cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		clientConn, clientChannels, clientRequests, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), config)
		if err != nil {
			done <- result{nil, err, ""}
			return
		}
		banner := string(clientConn.ServerVersion())
		client := ssh.NewClient(clientConn, clientChannels, clientRequests)
		done <- result{client, nil, banner}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case result := <-done:
			conn.Close()
			if result.err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: result.err, Banner: result.banner}
			}
			result.client.Close()
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: result.banner}
		default:
			conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: fmt.Errorf("timeout")}
		}
	case result := <-done:
		conn.Close()
		if result.err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: result.err, Banner: result.banner}
		}
		result.client.Close()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: result.banner}
	}
}

func init() { Register("ssh", BruteSSH) }
