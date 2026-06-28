package brute

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestStickyKeysVerdict(t *testing.T) {
	cases := []struct {
		name     string
		verdict  terminalWindowVerdict
		wantSev  string
		wantCode string
	}{
		{"clean-no-finding", terminalWindowClean, "", ""},
		{"changed-but-not-rect", terminalWindowChanged, "INFO", "rdp-stickykeys-inconclusive"},
		{"detected-terminal", terminalWindowDetected, "CRITICAL", "rdp-stickykeys"},
	}
	for _, c := range cases {
		got := stickyKeysVerdict(c.verdict)
		if c.wantCode == "" {
			if got != nil {
				t.Fatalf("%s: want nil, got %+v", c.name, got)
			}
			continue
		}
		if got == nil || got.Severity != c.wantSev || got.Code != c.wantCode {
			t.Fatalf("%s: got %+v want sev=%s code=%s", c.name, got, c.wantSev, c.wantCode)
		}
	}
}

// makePNG builds a PNG containing a solid background with an optional
// filled "window" rectangle. winColor is ignored when winW/winH == 0.
func makePNG(t *testing.T, w, h int, bg color.RGBA, winX, winY, winW, winH int, winColor color.RGBA) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, bg)
		}
	}
	for y := winY; y < winY+winH && y < h; y++ {
		for x := winX; x < winX+winW && x < w; x++ {
			img.SetRGBA(x, y, winColor)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

func TestDetectTerminalWindowEmptyInputs(t *testing.T) {
	if got := detectTerminalWindow(nil, nil); got != terminalWindowClean {
		t.Fatalf("nil/nil: got %v, want clean", got)
	}
	if got := detectTerminalWindow([]byte("garbage"), []byte("garbage")); got != terminalWindowClean {
		t.Fatalf("garbage: got %v, want clean", got)
	}
}

func TestDetectTerminalWindowIdenticalIsClean(t *testing.T) {
	bg := color.RGBA{0x20, 0x40, 0x80, 0xff}
	frame := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	if got := detectTerminalWindow(frame, frame); got != terminalWindowClean {
		t.Fatalf("identical frames: got %v, want clean", got)
	}
}

func TestDetectTerminalWindowCmdRectangleDetected(t *testing.T) {
	// Before: blue logon screen. After: same screen with a black cmd-style
	// window opened at the top-left. Even though the colour scheme is
	// different from any specific terminal, the brightness delta + rect
	// detection should flag it.
	bg := color.RGBA{0x20, 0x40, 0x80, 0xff}    // logon-screen-ish blue
	cmdBg := color.RGBA{0x05, 0x05, 0x05, 0xff} // near-black console
	before := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	after := makePNG(t, 1024, 768, bg, 50, 50, 600, 400, cmdBg)
	if got := detectTerminalWindow(before, after); got != terminalWindowDetected {
		t.Fatalf("cmd-shaped window: got %v, want detected", got)
	}
}

func TestDetectTerminalWindowPowerShellRectangleDetected(t *testing.T) {
	// Same setup but a blue PowerShell-style window — heuristic must
	// catch this, not just cmd's black-on-white palette.
	bg := color.RGBA{0xc0, 0xc0, 0xc0, 0xff}  // pale logon background
	psBg := color.RGBA{0x01, 0x36, 0xa3, 0xff} // PowerShell blue
	before := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	after := makePNG(t, 1024, 768, bg, 100, 100, 700, 450, psBg)
	if got := detectTerminalWindow(before, after); got != terminalWindowDetected {
		t.Fatalf("powershell-shaped window: got %v, want detected", got)
	}
}

func TestDetectTerminalWindowSparseChangeIsClean(t *testing.T) {
	// Below the 2% minimum: a 100x10 strip in a 1024x768 frame is ~0.13%.
	bg := color.RGBA{0x80, 0x80, 0x80, 0xff}
	other := color.RGBA{0x10, 0x10, 0x10, 0xff}
	before := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	after := makePNG(t, 1024, 768, bg, 0, 0, 100, 10, other)
	if got := detectTerminalWindow(before, after); got != terminalWindowClean {
		t.Fatalf("sparse change: got %v, want clean", got)
	}
}

func TestDetectTerminalWindowFullScreenRepaintIsClean(t *testing.T) {
	// Above the 80% maximum: entire frame flipped from light to dark.
	bg := color.RGBA{0xf0, 0xf0, 0xf0, 0xff}
	other := color.RGBA{0x05, 0x05, 0x05, 0xff}
	before := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	after := makePNG(t, 1024, 768, other, 0, 0, 0, 0, other)
	if got := detectTerminalWindow(before, after); got != terminalWindowClean {
		t.Fatalf("full-screen repaint: got %v, want clean", got)
	}
}

func TestDetectTerminalWindowScatteredChangeIsInconclusive(t *testing.T) {
	// Above 2% but pixels scattered across the screen (not a rectangle).
	bg := color.RGBA{0x80, 0x80, 0x80, 0xff}
	other := color.RGBA{0x10, 0x10, 0x10, 0xff}
	img := image.NewRGBA(image.Rect(0, 0, 1024, 768))
	for y := 0; y < 768; y++ {
		for x := 0; x < 1024; x++ {
			img.SetRGBA(x, y, bg)
		}
	}
	// Sprinkle ~3% of pixels across the WHOLE frame (not clustered).
	for y := 0; y < 768; y += 6 {
		for x := 0; x < 1024; x += 6 {
			img.SetRGBA(x, y, other)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	after := buf.Bytes()
	before := makePNG(t, 1024, 768, bg, 0, 0, 0, 0, bg)
	got := detectTerminalWindow(before, after)
	// Scattered pixels span the whole canvas so the bounding box covers
	// the entire frame — but the fill ratio inside that box is well below
	// 40%, so the verdict should be "changed, no rectangle".
	if got != terminalWindowChanged {
		t.Fatalf("scattered change: got %v, want changed", got)
	}
}
