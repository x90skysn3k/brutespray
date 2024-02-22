package brute

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func BruteSSH(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
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
	go func() {
		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
		done <- result{client, err}
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
