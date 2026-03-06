package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// HostView renders attempts grouped by host with a host selector.
type HostView struct {
	hosts        []string          // sorted host keys
	hostSet      map[string]bool   // for dedup
	selectedIdx  int
	attempts     map[string][]string // hostKey -> rendered lines
	width, height int
}

func NewHostView() HostView {
	return HostView{
		hostSet:  make(map[string]bool),
		attempts: make(map[string][]string),
	}
}

func (v *HostView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *HostView) AddAttempt(msg AttemptResultMsg, scheme *ColorScheme) {
	hostKey := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
	if !v.hostSet[hostKey] {
		v.hostSet[hostKey] = true
		v.hosts = append(v.hosts, hostKey)
		sort.Strings(v.hosts)
	}

	style, status := scheme.AttemptStyle(msg.Success, msg.Connected, msg.Retrying)

	line := fmt.Sprintf("  %s:%-15s  %s  %s", msg.User, msg.Password, status, msg.Duration.Round(1e6))
	v.attempts[hostKey] = append(v.attempts[hostKey], style.Render(line))

	// Cap per host
	if len(v.attempts[hostKey]) > 2000 {
		v.attempts[hostKey] = v.attempts[hostKey][len(v.attempts[hostKey])-2000:]
	}
}

func (v *HostView) NextHost() bool {
	if len(v.hosts) > 0 {
		v.selectedIdx = (v.selectedIdx + 1) % len(v.hosts)
		return true
	}
	return false
}

func (v *HostView) PrevHost() bool {
	if len(v.hosts) == 0 {
		return false
	}
	if v.selectedIdx == 0 {
		return false // at top, signal tab bar refocus
	}
	v.selectedIdx--
	return true
}

func (v *HostView) SelectedHost() string {
	if v.selectedIdx < len(v.hosts) {
		return v.hosts[v.selectedIdx]
	}
	return ""
}

func (v *HostView) View(scheme *ColorScheme, pausedHosts map[string]bool, hostStates map[string]*HostState) string {
	if len(v.hosts) == 0 {
		return lipgloss.NewStyle().Foreground(scheme.Muted).Render("  Waiting for hosts...")
	}

	// Left pane: host list
	leftWidth := 35
	rightWidth := v.width - leftWidth - 3
	if rightWidth < 20 {
		rightWidth = 20
	}

	var leftLines []string
	for i, h := range v.hosts {
		icon := "●"
		color := scheme.Success
		if pausedHosts[h] {
			icon = "⏸"
			color = scheme.Warning
		}
		if state, ok := hostStates[h]; ok && state.Completed {
			icon = "✓"
			color = scheme.Muted
		}
		prefix := "  "
		if i == v.selectedIdx {
			prefix = "▸ "
		}
		count := len(v.attempts[h])
		label := fmt.Sprintf("%s%s %s (%d)", prefix, icon, h, count)
		leftLines = append(leftLines, lipgloss.NewStyle().Foreground(color).Render(label))
	}

	leftPane := lipgloss.NewStyle().
		Width(leftWidth).
		Height(v.height).
		Render(strings.Join(leftLines, "\n"))

	// Right pane: attempts for selected host
	selected := v.SelectedHost()
	var rightContent string
	if lines, ok := v.attempts[selected]; ok {
		// Show last N lines that fit
		visibleLines := v.height
		start := 0
		if len(lines) > visibleLines {
			start = len(lines) - visibleLines
		}
		rightContent = strings.Join(lines[start:], "\n")
	}

	rightPane := lipgloss.NewStyle().
		Width(rightWidth).
		Height(v.height).
		Render(rightContent)

	divider := lipgloss.NewStyle().
		Foreground(scheme.Muted).
		Render(strings.TrimRight(strings.Repeat("│\n", v.height), "\n"))

	return lipgloss.JoinHorizontal(lipgloss.Top, leftPane, divider, rightPane)
}
