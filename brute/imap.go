package brute

import (
	"fmt"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteIMAP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		// modules.PrintSocksError("imap", fmt.Sprintf("%v", err))
		return false, false
	}
	// Client takes ownership of conn? No, we usually need to close it or client.Logout()

	c, err := client.New(conn)
	if err != nil {
		conn.Close()
		return false, true
	}
	defer c.Logout()

	err = c.Login(user, password)
	if err != nil {
		return false, true
	}

	return true, true
}
