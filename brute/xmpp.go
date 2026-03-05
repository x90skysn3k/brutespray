package brute

import (
	"strconv"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"gosrc.io/xmpp"
	"gosrc.io/xmpp/stanza"
)

func BruteXMPP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		session *xmpp.Client
		err     error
	}
	done := make(chan result, 1)

	// Dial outside the goroutine to avoid a data race on conn.
	conn, err := cm.Dial("tcp", hoststr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		defer conn.Close()

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
		_ = conn.SetDeadline(time.Now())
		select {
		case res := <-done:
			if res.err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: res.err}
			}
			presence := stanza.NewPresence(stanza.Attrs{})
			if err := res.session.Send(presence); err != nil {
				_ = res.session.Disconnect()
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
			}
			_ = res.session.Disconnect()
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
		}
	case res := <-done:
		if res.err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: res.err}
		}

		presence := stanza.NewPresence(stanza.Attrs{})
		if err := res.session.Send(presence); err != nil {
			_ = res.session.Disconnect()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		_ = res.session.Disconnect()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	}
}

func init() { Register("xmpp", BruteXMPP) }
