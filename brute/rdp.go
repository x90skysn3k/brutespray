package brute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/png"
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
	// Sticky-keys probe: only meaningful when the server accepts standard RDP
	// (no NLA), because that's the only mode where the GINA/logon screen is
	// reachable without credentials.
	if status == client.NLANotEnforced {
		c := &client.RdpClient{}
		before, after, stickyErr := c.CaptureLogonScreen(ctx, target, client.TriggerShift5x, timeout)
		c.Close()
		if stickyErr == nil {
			if f := stickyKeysVerdict(
				looksLikeCmdConsole(before),
				looksLikeCmdConsole(after),
				framebuffersDiffer(before, after),
			); f != nil {
				out = append(out, f)
			}
		}
	}
	return out
}

// stickyKeysVerdict produces a Finding (or nil) from the before/after analysis.
func stickyKeysVerdict(beforeCmd, afterCmd, differ bool) *Finding {
	if !differ {
		return nil
	}
	if afterCmd && !beforeCmd {
		return &Finding{
			Severity: "CRITICAL",
			Code:     "rdp-stickykeys",
			Message:  "sticky-keys backdoor detected (cmd.exe shell at logon screen)",
		}
	}
	return &Finding{
		Severity: "INFO",
		Code:     "rdp-stickykeys-inconclusive",
		Message:  "logon screen reacted to sticky-keys trigger but no console signature detected; manual verification recommended",
	}
}

// looksLikeCmdConsole applies a pixel-ratio heuristic to a PNG-encoded
// framebuffer snapshot: a cmd.exe window in its default colour scheme
// covers the top-left region of the screen with predominantly black
// pixels (background) and a small proportion of white pixels (text).
func looksLikeCmdConsole(pngBytes []byte) bool {
	if len(pngBytes) == 0 {
		return false
	}
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return false
	}
	b := img.Bounds()
	maxX := b.Min.X + 400
	if maxX > b.Max.X {
		maxX = b.Max.X
	}
	maxY := b.Min.Y + 200
	if maxY > b.Max.Y {
		maxY = b.Max.Y
	}
	var total, black, white int
	for y := b.Min.Y; y < maxY; y++ {
		for x := b.Min.X; x < maxX; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			r >>= 8
			g >>= 8
			bl >>= 8
			total++
			switch {
			case r < 32 && g < 32 && bl < 32:
				black++
			case r > 200 && g > 200 && bl > 200:
				white++
			}
		}
	}
	if total == 0 {
		return false
	}
	blackPct := float64(black) / float64(total)
	whitePct := float64(white) / float64(total)
	return blackPct > 0.65 && whitePct > 0.02 && whitePct < 0.15
}

// framebuffersDiffer reports whether two PNG-encoded framebuffer snapshots
// differ at the byte level. A length difference also counts as a difference.
func framebuffersDiffer(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if len(a) != len(b) {
		return true
	}
	return !bytes.Equal(a, b)
}
