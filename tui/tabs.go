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

// brandText is the compact brand name shown in the top-right of the tab bar.
const brandText = "BRUTESPRAY"

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

	tabLine := strings.Join(tabs, " ")

	// Brand + version right-aligned on the tab line, colored with the scheme's accent
	brandLabel := brandText
	if version != "" {
		brandLabel = brandText + " " + version
	}
	brand := lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(brandLabel)
	brandWidth := len(brandLabel)

	tabLineWidth := lipgloss.Width(tabLine)
	gap := width - tabLineWidth - brandWidth
	line1 := tabLine
	if gap > 0 {
		line1 = tabLine + strings.Repeat(" ", gap) + brand
	}

	// Separator line
	separator := lipgloss.NewStyle().
		Foreground(accentColor).
		Render(strings.Repeat("─", width))

	return line1 + "\n" + separator
}
