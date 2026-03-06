package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ErrorEntry holds a single error with timestamp.
type ErrorEntry struct {
	Message   string
	Timestamp time.Time
}

// ErrorsView shows a scrollable log of all errors.
type ErrorsView struct {
	entries       []ErrorEntry
	width, height int
}

func NewErrorsView() ErrorsView {
	return ErrorsView{}
}

func (v *ErrorsView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *ErrorsView) AddError(msg string, ts time.Time) {
	v.entries = append(v.entries, ErrorEntry{Message: msg, Timestamp: ts})
	if len(v.entries) > 500 {
		v.entries = v.entries[len(v.entries)-500:]
	}
}

func (v *ErrorsView) Count() int {
	return len(v.entries)
}

func (v *ErrorsView) View(scheme *ColorScheme) string {
	if len(v.entries) == 0 {
		return lipgloss.NewStyle().Foreground(scheme.Muted).Render("  No errors")
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(scheme.Error)
	timeStyle := lipgloss.NewStyle().Foreground(scheme.Muted)
	msgStyle := lipgloss.NewStyle().Foreground(scheme.Error)

	var lines []string
	lines = append(lines, headerStyle.Render(fmt.Sprintf("  Errors (%d)", len(v.entries))))
	lines = append(lines, lipgloss.NewStyle().Foreground(scheme.Muted).Render(
		"  "+strings.Repeat("─", v.width-4)))

	for _, e := range v.entries {
		ts := e.Timestamp.Format("15:04:05")
		line := fmt.Sprintf("  %s  %s", timeStyle.Render(ts), msgStyle.Render(e.Message))
		lines = append(lines, line)
	}

	// Show last entries that fit
	visibleLines := v.height
	start := 0
	if len(lines) > visibleLines {
		start = len(lines) - visibleLines
	}
	return strings.Join(lines[start:], "\n")
}
