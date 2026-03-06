package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
)

// AllView renders a scrollable log of all attempts.
type AllView struct {
	viewport viewport.Model
	lines    []string
	ready    bool
}

// NewAllView creates a new AllView.
func NewAllView() AllView {
	return AllView{}
}

func (v *AllView) SetSize(width, height int) {
	v.viewport.Width = width
	v.viewport.Height = height
	v.ready = true
	v.refreshContent()
}

func (v *AllView) AddAttempt(msg AttemptResultMsg, scheme *ColorScheme) {
	style, status := scheme.AttemptStyle(msg.Success, msg.Connected, msg.Retrying)

	var line string
	if msg.User == "" {
		line = fmt.Sprintf("[%s] %s:%d  pass:%-20s  %s  %s",
			msg.Service, msg.Host, msg.Port, msg.Password, status, msg.Duration.Round(1e6))
	} else {
		line = fmt.Sprintf("[%s] %s:%d  %s:%-15s  %s  %s",
			msg.Service, msg.Host, msg.Port, msg.User, msg.Password, status, msg.Duration.Round(1e6))
	}

	v.lines = append(v.lines, style.Render(line))

	// Ring buffer: keep last 5000 entries
	if len(v.lines) > 5000 {
		v.lines = v.lines[len(v.lines)-5000:]
	}

	v.refreshContent()
}

func (v *AllView) refreshContent() {
	if !v.ready {
		return
	}
	content := strings.Join(v.lines, "\n")
	v.viewport.SetContent(content)
	// Auto-scroll to bottom
	v.viewport.GotoBottom()
}

// View returns the rendered viewport.
func (v *AllView) View() string {
	if !v.ready {
		return "Initializing..."
	}
	return v.viewport.View()
}

// Viewport returns a pointer to the viewport for key handling.
func (v *AllView) Viewport() *viewport.Model {
	return &v.viewport
}
