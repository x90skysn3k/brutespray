package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) viewFindings() string {
	if len(m.findings) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Render("No findings yet. Pre-auth recon results (SSH bad-keys, RDP NLA, sticky-keys) appear here.")
	}
	var b strings.Builder
	for _, f := range m.findings {
		sev := f.Severity
		// Color by severity to match WriteFinding's scheme:
		// CRITICAL → red, HIGH → bright red, WARN → yellow, INFO → cyan
		var sevColor lipgloss.Color
		switch sev {
		case "CRITICAL":
			sevColor = "#ff5555"
		case "HIGH":
			sevColor = "#ff8888"
		case "WARN":
			sevColor = "#ffaa00"
		default:
			sevColor = "#00ffff"
		}
		sevStyled := lipgloss.NewStyle().Bold(true).Foreground(sevColor).Render("[" + sev + "]")
		cve := ""
		if f.CVE != "" {
			cve = " (" + f.CVE + ")"
		}
		b.WriteString(fmt.Sprintf("%s %s %s %s%s\n", sevStyled, f.Service, f.Target, f.Message, cve))
	}
	return b.String()
}
