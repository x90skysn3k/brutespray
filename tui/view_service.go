package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ServiceView renders attempts grouped by service.
type ServiceView struct {
	services    []string
	serviceSet  map[string]bool
	selectedIdx int
	attempts    map[string][]string
	width, height int
}

func NewServiceView() ServiceView {
	return ServiceView{
		serviceSet: make(map[string]bool),
		attempts:   make(map[string][]string),
	}
}

func (v *ServiceView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *ServiceView) AddAttempt(msg AttemptResultMsg, scheme *ColorScheme) {
	svc := msg.Service
	if !v.serviceSet[svc] {
		v.serviceSet[svc] = true
		v.services = append(v.services, svc)
		sort.Strings(v.services)
	}

	style, status := scheme.AttemptStyle(msg.Success, msg.Connected, msg.Retrying)

	hostPort := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
	creds := fmt.Sprintf("%s:%s", msg.User, msg.Password)
	if msg.User == "" {
		creds = fmt.Sprintf("pass:%s", msg.Password)
	}
	line := fmt.Sprintf("  %-*s  %-*s  %-*s",
		colWidthHostPort, hostPort,
		colWidthCreds, creds,
		colWidthStatus, status)
	v.attempts[svc] = append(v.attempts[svc], style.Render(line))
	if len(v.attempts[svc]) > 2000 {
		v.attempts[svc] = v.attempts[svc][len(v.attempts[svc])-2000:]
	}
}

func (v *ServiceView) NextService() bool {
	if len(v.services) > 0 {
		v.selectedIdx = (v.selectedIdx + 1) % len(v.services)
		return true
	}
	return false
}

func (v *ServiceView) PrevService() bool {
	if len(v.services) == 0 {
		return false
	}
	if v.selectedIdx == 0 {
		return false // at top, signal tab bar refocus
	}
	v.selectedIdx--
	return true
}

func (v *ServiceView) SelectedService() string {
	if v.selectedIdx < len(v.services) {
		return v.services[v.selectedIdx]
	}
	return ""
}

func (v *ServiceView) View(scheme *ColorScheme) string {
	if len(v.services) == 0 {
		return lipgloss.NewStyle().Foreground(scheme.Muted).Render("  Waiting for services...")
	}

	leftWidth := 25
	rightWidth := v.width - leftWidth - 3
	if rightWidth < 20 {
		rightWidth = 20
	}

	var leftLines []string
	for i, svc := range v.services {
		prefix := "  "
		if i == v.selectedIdx {
			prefix = "▸ "
		}
		count := len(v.attempts[svc])
		label := fmt.Sprintf("%s%s (%d)", prefix, svc, count)
		leftLines = append(leftLines, lipgloss.NewStyle().Foreground(scheme.Primary).Render(label))
	}

	leftPane := lipgloss.NewStyle().
		Width(leftWidth).
		Height(v.height).
		Render(strings.Join(leftLines, "\n"))

	selected := v.SelectedService()
	var rightContent string
	if lines, ok := v.attempts[selected]; ok {
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
