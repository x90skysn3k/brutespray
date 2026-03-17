package brute

import (
	"context"
	"strconv"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"gosrc.io/xmpp"
	"gosrc.io/xmpp/stanza"
)

func BruteXMPP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	portstr := strconv.Itoa(port)
	hoststr := host + ":" + portstr

	conn, err := cm.Dial("tcp", hoststr)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		defer conn.Close()
		go func() { <-ctx.Done(); _ = conn.SetDeadline(time.Now()) }()

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

		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		presence := stanza.NewPresence(stanza.Attrs{})
		if err := client.Send(presence); err != nil {
			_ = client.Disconnect()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		_ = client.Disconnect()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("xmpp", BruteXMPP) }
