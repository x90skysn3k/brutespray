package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func (m Model) viewFindings() string {
	if len(m.findings) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Render("No findings yet. Pre-auth recon results (SSH bad-keys, RDP NLA, sticky-keys) appear here.")
	}
	findings := m.findings
	if m.height > 0 {
		if max := m.contentHeight(); len(findings) > max {
			findings = findings[len(findings)-max:]
		}
	}

	var b strings.Builder
	for i, f := range findings {
		sev := f.Severity
		// Color by severity to match WriteFinding's scheme:
		// CRITICAL → red, HIGH → bright red, WARN → yellow, INFO → cyan.
		// Unknown/empty tokens stay visible but use neutral styling.
		var sevColor lipgloss.Color
		switch sev {
		case "CRITICAL":
			sevColor = "#ff5555"
		case "HIGH":
			sevColor = "#ff8888"
		case "WARN":
			sevColor = "#ffaa00"
		case "INFO":
			sevColor = "#00ffff"
		default:
			sevColor = "#888888"
		}
		sevStyled := lipgloss.NewStyle().Bold(true).Foreground(sevColor).Render("[" + sev + "]")
		cve := ""
		if f.CVE != "" {
			cve = " (" + f.CVE + ")"
		}
		code := ""
		if f.Code != "" {
			code = " [" + f.Code + "]"
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		line := fmt.Sprintf("%s %s %s %s%s%s", sevStyled, f.Service, f.Target, f.Message, code, cve)
		if m.width > 0 {
			line = ansi.Truncate(line, m.width, "…")
		}
		b.WriteString(line)
	}
	return b.String()
}
