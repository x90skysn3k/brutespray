package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// settingsField represents a single row in the settings view.
type settingsField struct {
	label    string
	editable bool
}

var settingsFields = []settingsField{
	{label: "Threads per Host", editable: true},
	{label: "Parallel Hosts", editable: true},
	// separator implied after index 1
	{label: "Elapsed", editable: false},
	{label: "Total Attempts", editable: false},
	{label: "Attempts/sec", editable: false},
	{label: "Success Rate", editable: false},
	{label: "Successes", editable: false},
	{label: "Conn Errors", editable: false},
	{label: "Auth Errors", editable: false},
}

// SettingsView renders editable settings and live performance stats.
type SettingsView struct {
	selectedIdx   int
	width, height int
	stats         modules.OutputStatsCopy
	pool          WorkerPoolController

	// Flash confirmation
	changedIdx int
	changedAt  time.Time
}

// NewSettingsView creates a new SettingsView.
func NewSettingsView(pool WorkerPoolController) SettingsView {
	return SettingsView{pool: pool, changedIdx: -1}
}

func (v *SettingsView) SetSize(width, height int) {
	v.width = width
	v.height = height
}

func (v *SettingsView) Update(stats modules.OutputStatsCopy) {
	v.stats = stats
}

// Next moves selection down. Returns false if already at the bottom.
func (v *SettingsView) Next() bool {
	if v.selectedIdx < len(settingsFields)-1 {
		v.selectedIdx++
		return true
	}
	return false
}

// Prev moves selection up. Returns false if already at the top (signal to refocus tab bar).
func (v *SettingsView) Prev() bool {
	if v.selectedIdx > 0 {
		v.selectedIdx--
		return true
	}
	return false
}

func (v *SettingsView) flash() {
	v.changedIdx = v.selectedIdx
	v.changedAt = time.Now()
}

// AdjustRight increases the selected editable field.
func (v *SettingsView) AdjustRight() {
	if v.pool == nil || v.selectedIdx >= len(settingsFields) {
		return
	}
	f := settingsFields[v.selectedIdx]
	if !f.editable {
		return
	}
	switch v.selectedIdx {
	case 0: // Threads per Host
		cur := v.pool.GetThreadsPerHost()
		if cur < 100 {
			v.pool.SetThreadsPerHost(cur + 1)
			v.flash()
		}
	case 1: // Parallel Hosts
		cur := v.pool.GetHostParallelism()
		if cur < 50 {
			v.pool.SetHostParallelism(cur + 1)
			v.flash()
		}
	}
}

// AdjustLeft decreases the selected editable field.
func (v *SettingsView) AdjustLeft() {
	if v.pool == nil || v.selectedIdx >= len(settingsFields) {
		return
	}
	f := settingsFields[v.selectedIdx]
	if !f.editable {
		return
	}
	switch v.selectedIdx {
	case 0: // Threads per Host
		cur := v.pool.GetThreadsPerHost()
		if cur > 1 {
			v.pool.SetThreadsPerHost(cur - 1)
			v.flash()
		}
	case 1: // Parallel Hosts
		cur := v.pool.GetHostParallelism()
		if cur > 1 {
			v.pool.SetHostParallelism(cur - 1)
			v.flash()
		}
	}
}

// IsEditable returns true if the currently selected field is editable.
func (v *SettingsView) IsEditable() bool {
	if v.selectedIdx >= len(settingsFields) {
		return false
	}
	return settingsFields[v.selectedIdx].editable
}

func (v *SettingsView) View(scheme *ColorScheme) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(scheme.Accent)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa")).Width(20)
	valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true)
	selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true).Background(scheme.Primary)
	arrowStyle := lipgloss.NewStyle().Foreground(scheme.Accent).Bold(true)
	successStyle := lipgloss.NewStyle().Foreground(scheme.Success).Bold(true)
	errorStyle := lipgloss.NewStyle().Foreground(scheme.Error)
	appliedStyle := lipgloss.NewStyle().Foreground(scheme.Success).Bold(true)

	s := v.stats
	elapsed := time.Since(s.StartTime)
	var aps float64
	if elapsed.Seconds() > 0 {
		aps = float64(s.TotalAttempts) / elapsed.Seconds()
	}
	var successRate float64
	if s.TotalAttempts > 0 {
		successRate = float64(s.SuccessfulAttempts) / float64(s.TotalAttempts) * 100
	}

	threadsPerHost := 0
	parallelHosts := 0
	if v.pool != nil {
		threadsPerHost = v.pool.GetThreadsPerHost()
		parallelHosts = v.pool.GetHostParallelism()
	}

	fieldValues := []string{
		fmt.Sprintf("%d", threadsPerHost),
		fmt.Sprintf("%d", parallelHosts),
		elapsed.Round(time.Second).String(),
		fmt.Sprintf("%d", s.TotalAttempts),
		fmt.Sprintf("%.1f", aps),
		fmt.Sprintf("%.2f%%", successRate),
		fmt.Sprintf("%d", s.SuccessfulAttempts),
		fmt.Sprintf("%d", s.ConnectionErrors),
		fmt.Sprintf("%d", s.AuthenticationErrors),
	}

	showApplied := v.changedIdx >= 0 && time.Since(v.changedAt) < 2*time.Second

	var lines []string
	lines = append(lines, titleStyle.Render("  Settings & Stats"))
	lines = append(lines, "")

	for i, f := range settingsFields {
		if i == 2 {
			lines = append(lines, lipgloss.NewStyle().Foreground(scheme.Muted).Render("  "+strings.Repeat("─", 40)))
			lines = append(lines, "")
		}

		prefix := "  "
		if i == v.selectedIdx {
			prefix = "▸ "
		}

		val := fieldValues[i]
		var rendered string
		if f.editable && i == v.selectedIdx {
			rendered = prefix + labelStyle.Render(f.label) + " " + arrowStyle.Render("◀") + " " + selectedStyle.Render(" "+val+" ") + " " + arrowStyle.Render("▶")
		} else if f.editable {
			rendered = prefix + labelStyle.Render(f.label) + "   " + valueStyle.Render(val)
		} else {
			vs := valueStyle
			if f.label == "Successes" || f.label == "Success Rate" {
				vs = successStyle
			} else if f.label == "Conn Errors" || f.label == "Auth Errors" {
				vs = errorStyle
			}
			rendered = prefix + labelStyle.Render(f.label) + " " + vs.Render(val)
		}

		// Show "Applied!" flash next to the changed field
		if showApplied && i == v.changedIdx {
			rendered += "  " + appliedStyle.Render("✓ Applied!")
		}

		lines = append(lines, rendered)
	}

	// Service breakdown
	if len(s.ServiceBreakdown) > 0 {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Foreground(scheme.Muted).Render("  "+strings.Repeat("─", 40)))
		lines = append(lines, titleStyle.Render("  Services"))
		for svc, count := range s.ServiceBreakdown {
			lines = append(lines, fmt.Sprintf("    %s %s",
				labelStyle.Render(svc+":"),
				valueStyle.Render(fmt.Sprintf("%d", count))))
		}
	}

	return strings.Join(lines, "\n")
}
