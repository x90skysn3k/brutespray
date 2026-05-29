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

func nlaFinding(status string) *Finding {
	switch status {
	case "required":
		return &Finding{Severity: "INFO", Code: "rdp-nla-required",
			Message: "NLA (CredSSP) enforced"}
	case "not-enforced":
		return &Finding{Severity: "WARN", Code: "rdp-nla-missing",
			Message: "NLA not enforced — server accepts standard RDP without pre-auth"}
	case "hybrid-ex":
		return &Finding{Severity: "INFO", Code: "rdp-nla-hybridex",
			Message: "HybridEx (NLA + CredSSP early-user auth) enforced"}
	}
	return nil
}

// ScanRDPRecon runs pre-auth RDP recon (NLA fingerprint, sticky-keys probe)
// against a single target. Returns a slice of findings to emit. Called once
// per host by the dispatcher before any brute attempts.
func ScanRDPRecon(host string, port int, timeout time.Duration) []*Finding {
	target := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	status, err := client.FingerprintNLA(ctx, target, timeout)
	if err != nil {
		return nil
	}
	var out []*Finding
	switch status {
	case client.NLARequired:
		out = append(out, nlaFinding("required"))
	case client.NLANotEnforced:
		out = append(out, nlaFinding("not-enforced"))
	case client.NLAHybridEx:
		out = append(out, nlaFinding("hybrid-ex"))
	}
	// Sticky-keys probe slots in here in Task A6.
	return out
}
