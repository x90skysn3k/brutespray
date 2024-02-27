package brute

import (
	"fmt"
	"strconv"
	"time"

	"gosrc.io/xmpp"
	"gosrc.io/xmpp/stanza"
)

func BruteXMPP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		session *xmpp.Client
		err     error
	}
	done := make(chan result)
	go func() {
		router := xmpp.NewRouter()
		config := &xmpp.Config{
			TransportConfiguration: xmpp.TransportConfiguration{
				Address: hoststr,
			},
			Jid:            user,
			Credential:     xmpp.Password(password),
			Insecure:       false,
			ConnectTimeout: int(timeout.Seconds()),
			StreamLogger:   nil,
		}

		client, err := xmpp.NewClient(config, router, func(err error) {})
		router.HandleFunc("message", func(s xmpp.Sender, p stanza.Packet) {})

		done <- result{client, err}
	}()

	select {
	case <-timer.C:
		return false, false
	case res := <-done:
		if res.err != nil {
			_ = res.err
			//log.Printf("Error while connecting: %v", res.err)
			return false, true
		}

		presence := stanza.NewPresence(stanza.Attrs{})
		if err := res.session.Send(presence); err != nil {
			_ = res.session.Disconnect()
			return false, true
		}

		err := res.session.Disconnect()
		if err != nil {
			fmt.Println(err)
		}
		return true, true
	}
}
