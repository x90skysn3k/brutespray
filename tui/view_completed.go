package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// CompletedView shows hosts that have finished processing.
type CompletedView struct {
	entries       []HostCompletedInfo
	width, height int
}

// HostCompletedInfo stores info about a completed host.
type HostCompletedInfo struct {
	Host          string
	Port          int
	Service       string
	TotalAttempts int64
	SuccessRate   float64
	AvgResponseMs float64
}

func NewCompletedView() CompletedView {
	return CompletedView{}
}

func (v *CompletedView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *CompletedView) AddCompleted(msg HostCompletedMsg) {
	v.entries = append(v.entries, HostCompletedInfo(msg))
	if len(v.entries) > 1000 {
		v.entries = v.entries[len(v.entries)-1000:]
	}
}

func (v *CompletedView) View(scheme *ColorScheme) string {
	if len(v.entries) == 0 {
		return lipgloss.NewStyle().Foreground(scheme.Muted).Render("  No completed hosts yet...")
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(scheme.Primary)
	rowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#cccccc"))

	var lines []string
	lines = append(lines, headerStyle.Render(
		fmt.Sprintf("  %-25s %-12s %10s %12s %12s", "Host", "Service", "Attempts", "Success %", "Avg Response")))
	lines = append(lines, lipgloss.NewStyle().Foreground(scheme.Muted).Render(
		"  "+safeRepeat("─", v.width-4)))

	for _, e := range v.entries {
		line := fmt.Sprintf("  %-25s %-12s %10d %11.1f%% %10.0fms",
			fmt.Sprintf("%s:%d", e.Host, e.Port),
			e.Service,
			e.TotalAttempts,
			e.SuccessRate*100,
			e.AvgResponseMs)
		lines = append(lines, rowStyle.Render(line))
	}

	visibleLines := v.height
	if visibleLines <= 0 {
		return ""
	}
	if len(lines) <= visibleLines {
		return strings.Join(lines, "\n")
	}
	headerLines := 2
	if visibleLines <= headerLines {
		return strings.Join(lines[:visibleLines], "\n")
	}
	entryLines := lines[headerLines:]
	start := 0
	if len(entryLines) > visibleLines-headerLines {
		start = len(entryLines) - (visibleLines - headerLines)
	}
	return strings.Join(append(lines[:headerLines:headerLines], entryLines[start:]...), "\n")
}

func (v *CompletedView) Count() int {
	return len(v.entries)
}
