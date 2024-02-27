package brute

import (
	"strconv"
	"time"

	"github.com/multiplay/go-ts3"
)

func BruteTeamSpeak(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr
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
