package tui

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/charmbracelet/lipgloss"
)

// ColorScheme holds the dynamic color theme for the TUI.
type ColorScheme struct {
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Accent    lipgloss.Color
	Success   lipgloss.Color
	Error     lipgloss.Color
	Warning   lipgloss.Color
	Muted     lipgloss.Color
	// Cycling colors for animated elements
	CycleColors []lipgloss.Color
	CycleIndex  int
}

// NewRandomColorScheme generates a harmonious color scheme from a random hue.
func NewRandomColorScheme() ColorScheme {
	hue := rand.Float64() * 360

	return ColorScheme{
		Primary:   hslToHex(hue, 0.7, 0.6),
		Secondary: hslToHex(hue+30, 0.6, 0.5),
		Accent:    hslToHex(hue+180, 0.8, 0.6),
		Success:   lipgloss.Color("#00ff88"),
		Error:     lipgloss.Color("#ff4444"),
		Warning:   lipgloss.Color("#ffaa44"),
		Muted:     lipgloss.Color("#666666"),
		CycleColors: []lipgloss.Color{
			hslToHex(hue, 0.8, 0.65),
			hslToHex(hue+45, 0.8, 0.65),
			hslToHex(hue+90, 0.8, 0.65),
			hslToHex(hue+135, 0.8, 0.65),
			hslToHex(hue+180, 0.8, 0.65),
			hslToHex(hue+225, 0.8, 0.65),
			hslToHex(hue+270, 0.8, 0.65),
			hslToHex(hue+315, 0.8, 0.65),
		},
	}
}

// CycleColor returns the next color in the cycle and advances the index.
func (cs *ColorScheme) CycleColor() lipgloss.Color {
	c := cs.CycleColors[cs.CycleIndex%len(cs.CycleColors)]
	cs.CycleIndex++
	return c
}

// AttemptStyle returns the appropriate style and status label for an attempt result.
// Colors: SUCCESS = green, FAILED = amber/yellow, CONN ERR / RETRY = red
func (cs *ColorScheme) AttemptStyle(success, connected, retrying bool) (lipgloss.Style, string) {
	switch {
	case success && connected:
		return lipgloss.NewStyle().Foreground(cs.Success).Bold(true), "SUCCESS"
	case !success && connected:
		return lipgloss.NewStyle().Foreground(cs.Warning), "INVALID"
	case retrying:
		return lipgloss.NewStyle().Foreground(cs.Error), "RETRY"
	default:
		return lipgloss.NewStyle().Foreground(cs.Error), "CONN ERR"
	}
}

// hslToHex converts HSL (hue 0-360, saturation 0-1, lightness 0-1) to a hex color.
func hslToHex(h, s, l float64) lipgloss.Color {
	h = math.Mod(h, 360)
	if h < 0 {
		h += 360
	}
	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2

	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}

	ri := int((r + m) * 255)
	gi := int((g + m) * 255)
	bi := int((b + m) * 255)
	return lipgloss.Color(fmt.Sprintf("#%02x%02x%02x", ri, gi, bi))
}
