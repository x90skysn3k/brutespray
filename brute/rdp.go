package brute

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/pdu"
)

func BruteRDP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, domain string) *BruteResult {
	glog.SetLevel(pdu.STREAM_LOW)
	logger := log.New(io.Discard, "", 0)
	glog.SetLogger(logger)

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		target := fmt.Sprintf("%s:%d", host, port)

		// Prepend domain to user if provided
		loginUser := user
		if domain != "" {
			loginUser = domain + "\\" + user
		}

		rdpClient := &client.RdpClient{}
		err := rdpClient.Login(ctx, target, loginUser, password, 800, 600)
		if err != nil {
			// Check if it's a dial error (connection failure) vs protocol error
			if ctx.Err() != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer rdpClient.Close()

		// Wait for auth result via events
		success := make(chan bool, 1)

		rdpClient.On("error", func(e error) {
			success <- false
		})
		rdpClient.On("close", func() {
			success <- false
		})
		rdpClient.On("ready", func() {
			success <- true
		})
		rdpClient.On("success", func() {
			success <- true
		})

		select {
		case result := <-success:
			return &BruteResult{AuthSuccess: result, ConnectionSuccess: true}
		case <-ctx.Done():
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: ctx.Err()}
		}
	})
}

func init() { RegisterWithDomain("rdp", BruteRDP) }
