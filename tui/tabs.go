package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Tab represents the different view tabs.
type Tab int

const (
	TabAll Tab = iota
	TabByHost
	TabByService
	TabCompleted
	TabSuccess
	TabErrors
	TabSettings
	tabCount // sentinel for total count
)

var tabNames = []string{"All", "By Host", "By Service", "Completed", "Successes", "Errors", "Settings"}

// renderRainbowBrand renders "BRUTESPRAY" with each character in a different
// cycling color from the scheme, creating a rainbow gradient effect.
func renderRainbowBrand(text string, scheme *ColorScheme) string {
	var b strings.Builder
	colors := scheme.CycleColors
	for i, ch := range text {
		color := colors[i%len(colors)]
		style := lipgloss.NewStyle().Foreground(color).Bold(true)
		b.WriteString(style.Render(string(ch)))
	}
	return b.String()
}

// RenderTabBar renders the tab bar at the top of the screen.
func RenderTabBar(activeTab Tab, width int, scheme *ColorScheme, badges map[Tab]int, tabBarFocused bool, version string) string {
	var tabs []string

	accentColor := scheme.CycleColor()

	activeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#ffffff")).
		Background(lipgloss.AdaptiveColor{Light: string(accentColor), Dark: string(accentColor)}).
		Padding(0, 2)

	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")).
		Padding(0, 2)

	// When content is focused, dim the tab bar slightly
	if !tabBarFocused {
		activeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accentColor).
			Padding(0, 2)
	}

	for i, name := range tabNames {
		tab := Tab(i)
		label := name
		if count, ok := badges[tab]; ok && count > 0 {
			label = fmt.Sprintf("%s (%d)", name, count)
		}
		if tab == activeTab {
			tabs = append(tabs, activeStyle.Render(label))
		} else {
			tabs = append(tabs, inactiveStyle.Render(label))
		}
	}

	bar := strings.Join(tabs, " ")

	// Right-aligned rainbow branding
	if version != "" {
		brandText := "BRUTESPRAY " + version
		brand := renderRainbowBrand(brandText, scheme)
		barLen := lipgloss.Width(bar)
		brandLen := lipgloss.Width(brand)
		gap := width - barLen - brandLen - 1
		if gap > 0 {
			bar = bar + strings.Repeat(" ", gap) + brand
		}
	}

	separator := lipgloss.NewStyle().
		Foreground(accentColor).
		Render(strings.Repeat("─", width))

	return bar + "\n" + separator
}
