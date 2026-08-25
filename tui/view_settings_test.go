package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestSettingsViewRendersZeroElapsedForUninitializedStats(t *testing.T) {
	view := NewSettingsView(&settingsViewTestPool{threadsPerHost: 4, hostParallelism: 2})
	view.Update(modules.OutputStatsCopy{TotalAttempts: 37})

	out := view.View(settingsViewTestScheme())
	elapsedLine := lineContaining(t, out, "Elapsed")
	if !strings.Contains(elapsedLine, "0s") {
		t.Fatalf("Elapsed row for zero StartTime = %q, want visible 0s", elapsedLine)
	}
	if strings.Contains(elapsedLine, "2562047h") {
		t.Fatalf("Elapsed row leaked bogus zero-time duration: %q", elapsedLine)
	}
}

func TestSettingsViewRendersServiceBreakdownSorted(t *testing.T) {
	view := NewSettingsView(&settingsViewTestPool{threadsPerHost: 4, hostParallelism: 2})
	view.Update(modules.OutputStatsCopy{
		ServiceBreakdown: map[string]int{
			"ssh":      4,
			"ftp":      1,
			"telnet":   5,
			"rdp":      3,
			"http-alt": 2,
		},
	})

	wantOrder := []string{"ftp:", "http-alt:", "rdp:", "ssh:", "telnet:"}
	for range 20 {
		out := view.View(settingsViewTestScheme())
		assertVisibleOrder(t, out, wantOrder)
	}
}

func lineContaining(t *testing.T, out, needle string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("output missing line containing %q: %s", needle, out)
	return ""
}

func assertVisibleOrder(t *testing.T, out string, wantOrder []string) {
	t.Helper()
	previous := -1
	for _, want := range wantOrder {
		idx := strings.Index(out, want)
		if idx == -1 {
			t.Fatalf("output missing service %q: %s", want, out)
		}
		if idx <= previous {
			t.Fatalf("services rendered out of order; want %v in output: %s", wantOrder, out)
		}
		previous = idx
	}
}

type settingsViewTestPool struct {
	threadsPerHost  int
	hostParallelism int
}

func (p *settingsViewTestPool) PauseHost(string)         {}
func (p *settingsViewTestPool) ResumeHost(string)        {}
func (p *settingsViewTestPool) PauseAll()                {}
func (p *settingsViewTestPool) ResumeAll()               {}
func (p *settingsViewTestPool) Stop()                    {}
func (p *settingsViewTestPool) SetThreadsPerHost(n int)  { p.threadsPerHost = n }
func (p *settingsViewTestPool) SetHostParallelism(n int) { p.hostParallelism = n }
func (p *settingsViewTestPool) GetThreadsPerHost() int   { return p.threadsPerHost }
func (p *settingsViewTestPool) GetHostParallelism() int  { return p.hostParallelism }

func settingsViewTestScheme() *ColorScheme {
	return &ColorScheme{
		Primary:     lipgloss.Color("#ffffff"),
		Secondary:   lipgloss.Color("#dddddd"),
		Accent:      lipgloss.Color("#00ffff"),
		Success:     lipgloss.Color("#00ff88"),
		Error:       lipgloss.Color("#ff4444"),
		Warning:     lipgloss.Color("#ffaa44"),
		Muted:       lipgloss.Color("#666666"),
		CycleColors: []lipgloss.Color{lipgloss.Color("#00ffff")},
	}
}
