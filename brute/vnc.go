package brute

import (
	"fmt"
	"time"

	"github.com/mitchellh/go-vnc"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: password,
			},
		},
	}

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := cm.Dial("tcp", addr)
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
