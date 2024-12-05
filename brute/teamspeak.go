package brute

import (
	"strconv"
	"time"

	"github.com/multiplay/go-ts3"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteTeamSpeak(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr

	cm, err := modules.NewConnectionManager(socks5, timeout)
	if err != nil {
		return false, false
	}

	conn, err := cm.Dial("tcp", hoststr)
	if err != nil {
		return false, false
	}
	defer conn.Close()

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
