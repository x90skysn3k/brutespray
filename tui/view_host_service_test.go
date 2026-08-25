package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func TestHostSidebarShowsTotalAttemptsBeyondRenderBufferCap(t *testing.T) {
	view := NewHostView()
	view.SetSize(100, 6)
	scheme := sidebarTestScheme()

	for i := range 2001 {
		view.AddAttempt(sidebarAttemptForTest(i, "10.0.0.5", 22, "ssh"), scheme)
	}

	out := view.View(scheme, map[string]bool{}, map[string]*HostState{})
	if !strings.Contains(out, "10.0.0.5:22 (2001)") {
		t.Fatalf("host sidebar did not show true attempt total beyond render cap: %s", out)
	}
}

func TestServiceSidebarShowsTotalAttemptsBeyondRenderBufferCap(t *testing.T) {
	view := NewServiceView()
	view.SetSize(100, 6)
	scheme := sidebarTestScheme()

	for i := range 2001 {
		view.AddAttempt(sidebarAttemptForTest(i, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), 22, "ssh"), scheme)
	}

	out := view.View(scheme)
	if !strings.Contains(out, "ssh (2001)") {
		t.Fatalf("service sidebar did not show true attempt total beyond render cap: %s", out)
	}
}

func sidebarAttemptForTest(i int, host string, port int, service string) AttemptResultMsg {
	return AttemptResultMsg{
		Host:      host,
		Port:      port,
		Service:   service,
		User:      fmt.Sprintf("user%d", i),
		Password:  fmt.Sprintf("pass%d", i),
		Connected: true,
		Duration:  time.Duration(i+1) * time.Millisecond,
	}
}

func sidebarTestScheme() *ColorScheme {
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
