package brute

import (
	"strconv"
	"time"

	"github.com/multiplay/go-ts3"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTeamSpeak(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr

	// NOTE: The go-ts3 library doesn't support custom dialers, so SOCKS5
	// proxy and interface binding do not apply to the actual TS3 connection.
	// The CM dial here serves only as a reachability check.
	conn, err := cm.Dial("tcp", hoststr)
	if err != nil {
		return false, false
	}
	conn.Close()

	c, err := ts3.NewClient(hoststr, ts3.Timeout(timeout))
	if err != nil {
		return false, false
	}
	defer c.Close()

	err = c.Login(user, password)
	if err != nil {
		return false, true
	}

	if _, err := c.Version(); err != nil {
		return false, true
	}

	return true, true
}
