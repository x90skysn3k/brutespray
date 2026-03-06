package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// SuccessView shows all successful credential finds.
type SuccessView struct {
	entries       []AttemptResultMsg
	width, height int
}

func NewSuccessView() SuccessView {
	return SuccessView{}
}

func (v *SuccessView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *SuccessView) AddSuccess(msg AttemptResultMsg) {
	v.entries = append(v.entries, msg)
	if len(v.entries) > 1000 {
		v.entries = v.entries[len(v.entries)-1000:]
	}
}

func (v *SuccessView) View(scheme *ColorScheme) string {
	if len(v.entries) == 0 {
		return lipgloss.NewStyle().Foreground(scheme.Muted).Render("  No successful credentials yet...")
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(scheme.Success)
	rowStyle := lipgloss.NewStyle().Foreground(scheme.Success)

	var lines []string
	lines = append(lines, headerStyle.Render(
		fmt.Sprintf("  %-12s %-22s %-18s %-20s %s", "Service", "Host", "User", "Password", "Duration")))
	lines = append(lines, lipgloss.NewStyle().Foreground(scheme.Success).Render(
		"  "+strings.Repeat("─", v.width-4)))

	for _, e := range v.entries {
		line := fmt.Sprintf("  %-12s %-22s %-18s %-20s %s",
			e.Service,
			fmt.Sprintf("%s:%d", e.Host, e.Port),
			e.User,
			e.Password,
			e.Duration.Round(1e6))
		lines = append(lines, rowStyle.Render(line))
	}

	visibleLines := v.height
	start := 0
	if len(lines) > visibleLines {
		start = len(lines) - visibleLines
	}
	return strings.Join(lines[start:], "\n")
}

func (v *SuccessView) Count() int {
	return len(v.entries)
}
