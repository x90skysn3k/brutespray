package brute

import (
	"fmt"
	"time"

	"github.com/mitchellh/go-vnc"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteVNC(host string, port int, user string, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: password,
			},
		},
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
