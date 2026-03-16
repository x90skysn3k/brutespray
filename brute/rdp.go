package brute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/pdu"
)

func BruteRDP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	glog.SetLevel(pdu.STREAM_LOW)
	logger := log.New(io.Discard, "", 0)
	glog.SetLogger(logger)

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		target := fmt.Sprintf("%s:%d", host, port)

		loginUser := user
		if params["domain"] != "" {
			loginUser = params["domain"] + "\\" + user
		}

		rdpClient := &client.RdpClient{}
		err := rdpClient.LoginAuthOnly(ctx, target, loginUser, password)
		if err != nil {
			var rdpErr *core.RDPError
			if errors.As(err, &rdpErr) {
				switch rdpErr.Kind {
				case core.ErrKindAuth:
					return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
				case core.ErrKindNetwork, core.ErrKindTimeout:
					return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
				}
			}
			if ctx.Err() != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer rdpClient.Close()

		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("rdp", BruteRDP) }
