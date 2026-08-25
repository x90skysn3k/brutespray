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
	"os"
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

func init() {
	Register("rdp", BruteRDP)
	RegisterPreAuthProbe("rdp", PreAuthProbe{
		Code:        "rdp-recon",
		Description: "RDP NLA fingerprint and sticky-keys probe",
		Default:     true,
		Run: func(ctx context.Context, target PreAuthTarget) ([]Finding, error) {
			findings := ScanRDPReconContext(ctx, target.Host, target.Port, target.Timeout)
			out := make([]Finding, 0, len(findings))
			for _, finding := range findings {
				out = append(out, *finding)
			}
			return out, nil
		},
	})
}

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

func ScanRDPReconContext(ctx context.Context, host string, port int, timeout time.Duration) []*Finding {
	target := fmt.Sprintf("%s:%d", host, port)
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
			if f := stickyKeysVerdict(detectTerminalWindow(before, after)); f != nil {
				out = append(out, f)
			}
		} else {
			// Probe error suppressed from output — emitting a stickykeys
			// finding without a successful capture would mislead. Diagnostics
			// land on stderr for operators who care.
			fmt.Fprintf(os.Stderr, "rdp sticky-keys probe %s: %v\n", target, stickyErr)
		}
	}
	return out
}

// ScanRDPRecon runs pre-auth RDP recon (NLA fingerprint, sticky-keys probe)
// against a single target. Returns a slice of findings to emit. Called once
// per host by the dispatcher before any brute attempts.
func ScanRDPRecon(host string, port int, timeout time.Duration) []*Finding {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return ScanRDPReconContext(ctx, host, port, timeout)
}

// terminalWindowVerdict captures the outcome of the post-trigger
// framebuffer analysis.
type terminalWindowVerdict int

const (
	// terminalWindowClean: too few pixels changed (or too many — likely a
	// full-screen repaint), so no isolated window appeared.
	terminalWindowClean terminalWindowVerdict = iota
	// terminalWindowChanged: pixels changed in the right range but did NOT
	// form a rectangular region — the trigger produced some repaint but
	// nothing terminal-shaped.
	terminalWindowChanged
	// terminalWindowDetected: pixels changed in a rectangular region
	// consistent with a terminal-style window opening.
	terminalWindowDetected
)

// Brightness-difference thresholds for terminal-window detection. These
// thresholds and the rectangle-fill-ratio gate are adapted from Praetorian's
// Brutus project (Apache 2.0), which exercises the same algorithm against
// real-world Windows RDP targets:
//
//	https://github.com/praetorian-inc/brutus/blob/main/internal/plugins/rdp/analyze.go
const (
	pixelChangeThreshold     = 30  // per-pixel brightness delta to count as "changed"
	minChangedPercent        = 2.0 // <2% changed → noise, no window
	maxChangedPercent        = 80.0
	rectangleFillRatioThresh = 0.4 // changed pixels must fill ≥40% of their bounding box
)

// stickyKeysVerdict produces a Finding (or nil) from a terminalWindow verdict.
func stickyKeysVerdict(v terminalWindowVerdict) *Finding {
	switch v {
	case terminalWindowDetected:
		return &Finding{
			Severity: "CRITICAL",
			Code:     "rdp-stickykeys",
			Message:  "sticky-keys backdoor detected (terminal window opened at logon screen)",
		}
	case terminalWindowChanged:
		return &Finding{
			Severity: "INFO",
			Code:     "rdp-stickykeys-inconclusive",
			Message:  "logon screen reacted to sticky-keys trigger but no terminal-shaped window detected; manual verification recommended",
		}
	}
	return nil
}

// detectTerminalWindow analyses the pixel-level difference between two
// PNG-encoded framebuffer snapshots and reports whether the post-trigger
// frame contains a new rectangular window consistent with a terminal
// (cmd.exe, PowerShell, or any other shell). Bg-color agnostic — a black
// cmd window and a blue PowerShell window both register as "detected"
// because the algorithm looks at WHERE pixels changed, not WHICH colors
// they took.
//
// Algorithm (adapted from praetorian-inc/brutus, Apache 2.0):
//  1. Decode both PNGs to RGBA buffers of the same dimensions
//  2. For every pixel, compute the brightness delta and mark "changed"
//     when the delta exceeds pixelChangeThreshold
//  3. If <minChangedPercent of pixels changed → clean (noise)
//  4. If >maxChangedPercent of pixels changed → clean (full-screen repaint)
//  5. Otherwise compute the bounding box of changed pixels and the fill
//     ratio. Fill ratio ≥ rectangleFillRatioThresh + boundingArea ≥ 1% of
//     screen → detected (terminal-shaped window). Else → changed-but-no-rect.
func detectTerminalWindow(beforePNG, afterPNG []byte) terminalWindowVerdict {
	before, ok1 := decodeRGBA(beforePNG)
	after, ok2 := decodeRGBA(afterPNG)
	if !ok1 || !ok2 || before.Bounds() != after.Bounds() {
		return terminalWindowClean
	}
	b := before.Bounds()
	w, h := b.Dx(), b.Dy()
	if w == 0 || h == 0 {
		return terminalWindowClean
	}

	changed := 0
	minX, minY := w, h
	maxX, maxY := 0, 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if pixelBrightnessDelta(before, after, b.Min.X+x, b.Min.Y+y) > pixelChangeThreshold {
				changed++
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}

	total := w * h
	pct := float64(changed) / float64(total) * 100.0
	if pct < minChangedPercent || pct > maxChangedPercent {
		return terminalWindowClean
	}

	if maxX <= minX || maxY <= minY {
		return terminalWindowChanged
	}
	boundingArea := (maxX - minX + 1) * (maxY - minY + 1)
	fillRatio := float64(changed) / float64(boundingArea)
	if fillRatio >= rectangleFillRatioThresh && boundingArea >= total/100 {
		return terminalWindowDetected
	}
	return terminalWindowChanged
}

func decodeRGBA(pngBytes []byte) (*image.RGBA, bool) {
	if len(pngBytes) == 0 {
		return nil, false
	}
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return nil, false
	}
	if rgba, ok := img.(*image.RGBA); ok {
		return rgba, true
	}
	b := img.Bounds()
	rgba := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			rgba.Set(x, y, img.At(x, y))
		}
	}
	return rgba, true
}

func pixelBrightnessDelta(a, bImg *image.RGBA, x, y int) int {
	ra, ga, ba, _ := a.At(x, y).RGBA()
	rb, gb, bb, _ := bImg.At(x, y).RGBA()
	la := (int(ra>>8) + int(ga>>8) + int(ba>>8)) / 3
	lb := (int(rb>>8) + int(gb>>8) + int(bb>>8)) / 3
	if la > lb {
		return la - lb
	}
	return lb - la
}
