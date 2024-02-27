package brute

import (
	"strconv"
	"time"

	"github.com/multiplay/go-ts3"
)

func BruteTeamSpeak(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr
	c, err := ts3.NewClient(hoststr)
	if err != nil {
		_ = err
		return false, false
	}
	defer c.Close()

	timeoutChan := time.After(timeout)

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-done:
			return
		case <-timeoutChan:
		}
	}()

	if err := c.Login(user, password); err != nil {
		_ = err
		return false, true
	}

	if _, err := c.Version(); err != nil {
		_ = err
		return false, true
	} else {
		return true, true
	}
}
