package brute

import (
	"fmt"
	"net"
	"time"

	"github.com/mitchellh/go-vnc"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration) (bool, bool) {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: password,
			},
		},
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	client, err := vnc.Client(conn, config)
	if err != nil {
		return false, true
	}
	defer client.Close()

	return true, true
}
