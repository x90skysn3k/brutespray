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
	v.AddAttempts([]AttemptResultMsg{msg}, scheme)
}

func (v *AllView) AddAttempts(msgs []AttemptResultMsg, scheme *ColorScheme) {
	if len(msgs) == 0 {
		return
	}

	for _, msg := range msgs {
		style, status := scheme.AttemptStyle(msg.Success, msg.Connected, msg.Retrying)

		hostPort := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
		creds := fmt.Sprintf("%s:%s", msg.User, msg.Password)
		if msg.User == "" {
			creds = fmt.Sprintf("pass:%s", msg.Password)
		}
		line := fmt.Sprintf("[%-*s] %-*s  %-*s  %-*s  %*s",
			colWidthService, msg.Service,
			colWidthHostPort, hostPort,
			colWidthCreds, creds,
			colWidthStatus, status,
			colWidthDuration, msg.Duration.Round(1e6))

		v.lines = append(v.lines, style.Render(line))
	}

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
	wasPinned := v.viewport.AtBottom()
	content := strings.Join(v.lines, "\n")
	v.viewport.SetContent(content)
	if wasPinned {
		v.viewport.GotoBottom()
	}
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
