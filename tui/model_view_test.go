package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func TestModelViewDoesNotPanicAtNarrowWidthsWithPopulatedTabs(t *testing.T) {
	m := readyModelForViewTest(t, 3, 10)
	m = updateModelForViewTest(t, m, BatchAttemptMsg{
		attemptForViewTest(1, true),
		attemptForViewTest(2, false),
	})
	m = updateModelForViewTest(t, m, ErrorMsg{Message: "dial timeout while connecting", Timestamp: fixedViewTestTime})
	m = updateModelForViewTest(t, m, HostCompletedMsg{Host: "10.0.0.1", Port: 22, Service: "ssh", TotalAttempts: 2, SuccessRate: 0.5, AvgResponseMs: 12})
	m = updateModelForViewTest(t, m, FindingMsg{Entry: FindingEntry{Severity: "WARN", Service: "rdp", Target: "10.0.0.2:3389", Message: "NLA not enforced", Time: fixedViewTestTime}})

	for _, tc := range []struct {
		name string
		tab  Tab
	}{
		{name: "all tab and status", tab: TabAll},
		{name: "completed tab", tab: TabCompleted},
		{name: "success tab", tab: TabSuccess},
		{name: "errors tab", tab: TabErrors},
		{name: "findings tab", tab: TabFindings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := m
			model.activeTab = tc.tab
			out := renderViewWithoutPanic(t, model)
			if out == "" {
				t.Fatalf("rendered empty frame for active tab %v at width %d", tc.tab, model.width)
			}
		})
	}
}

func TestAllTabManualScrollIsPreservedWhenAttemptsArrive(t *testing.T) {
	m := readyModelForViewTest(t, 80, 9)
	m = updateModelForViewTest(t, m, attemptsForViewTest(12, 0))

	bottomBefore := m.allView.Viewport().YOffset
	if bottomBefore <= 1 {
		t.Fatalf("setup did not produce a scrollable All tab: bottom offset = %d", bottomBefore)
	}

	const manualOffset = 1
	m.allView.Viewport().SetYOffset(manualOffset)
	m = updateModelForViewTest(t, m, BatchAttemptMsg{attemptForViewTest(99, false)})
	if got := m.allView.Viewport().YOffset; got != manualOffset {
		t.Fatalf("manual All-tab scroll offset changed to %d after a live attempt, want %d", got, manualOffset)
	}

	stuck := readyModelForViewTest(t, 80, 9)
	stuck = updateModelForViewTest(t, stuck, attemptsForViewTest(12, 200))
	bottomBefore = stuck.allView.Viewport().YOffset
	if bottomBefore <= 1 {
		t.Fatalf("setup did not produce a scrollable stuck-at-bottom All tab: bottom offset = %d", bottomBefore)
	}
	stuck = updateModelForViewTest(t, stuck, BatchAttemptMsg{attemptForViewTest(299, false)})
	if got := stuck.allView.Viewport().YOffset; got <= bottomBefore {
		t.Fatalf("All tab did not follow new attempts while already at bottom: offset = %d, previous bottom = %d", got, bottomBefore)
	}
}

func TestModelViewShowsFindingAndErrorBadgesUpdatedThroughMessages(t *testing.T) {
	m := readyModelForViewTest(t, 120, 12)
	m = updateModelForViewTest(t, m, ErrorMsg{Message: "ssh handshake failed", Timestamp: fixedViewTestTime})
	m = updateModelForViewTest(t, m, FindingMsg{Entry: FindingEntry{Severity: "INFO", Service: "ssh", Target: "10.0.0.5:22", Message: "known bad host key", Time: fixedViewTestTime}})

	out := renderViewWithoutPanic(t, m)
	for _, want := range []string{"Errors (1)", "Findings (1)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered model missing badge %q: %s", want, out)
		}
	}
}

func TestModelViewKeepsFindingsFooterVisibleWhenContentOverflows(t *testing.T) {
	m := readyModelForViewTest(t, 80, 10)
	for i := range 25 {
		m = updateModelForViewTest(t, m, FindingMsg{Entry: FindingEntry{
			Severity: "WARN",
			Service:  "rdp",
			Target:   fmt.Sprintf("10.0.0.%d:3389", i+1),
			Message:  fmt.Sprintf("overflow finding %02d", i+1),
			Time:     fixedViewTestTime.Add(time.Duration(i) * time.Second),
		}})
	}
	m.activeTab = TabFindings

	out := renderViewWithoutPanic(t, m)
	if !strings.Contains(out, "ctrl+c×2") {
		t.Fatalf("Findings frame dropped footer quit hint when content overflowed: %s", out)
	}
}

func TestModelViewKeepsFindingsFooterVisibleWhenLongRowsWrap(t *testing.T) {
	m := readyModelForViewTest(t, 120, 14)
	longCode := "RDP_" + strings.Repeat("PREAUTH_DISCOVERY_CODE_", 8)
	longTarget := "host-" + strings.Repeat("target-segment-", 10) + ":3389"
	spaceHeavyMessage := strings.Repeat("NLA disabled finding includes a very verbose remediation hint ", 6)
	for i := range 4 {
		m = updateModelForViewTest(t, m, FindingMsg{Entry: FindingEntry{
			Severity: "WARN",
			Code:     fmt.Sprintf("%s%02d", longCode, i+1),
			Service:  "rdp",
			Target:   fmt.Sprintf("%s-%02d", longTarget, i+1),
			Message:  fmt.Sprintf("%s case %02d %s", spaceHeavyMessage, i+1, strings.Repeat("unbrokenmessagechunk", 6)),
			Time:     fixedViewTestTime.Add(time.Duration(i) * time.Second),
		}})
	}
	m.activeTab = TabFindings

	out := renderViewWithoutPanic(t, m)
	visible := visibleTerminalRowsForViewTest(t, out, m.width, m.height)
	if !strings.Contains(visible, "ctrl+c×2") {
		t.Fatalf("Findings frame dropped footer quit hint after long rows wrapped to %dx%d terminal:\n%s", m.width, m.height, visible)
	}
}

func visibleTerminalRowsForViewTest(t *testing.T, frame string, width, height int) string {
	t.Helper()
	if width <= 0 || height <= 0 {
		t.Fatalf("terminal dimensions must be positive, got %dx%d", width, height)
	}

	rows := make([]string, 0, height)
	for _, logicalLine := range strings.Split(frame, "\n") {
		wrapped := strings.Split(ansi.Wrap(logicalLine, width, ""), "\n")
		rows = append(rows, wrapped...)
		if len(rows) >= height {
			break
		}
	}
	if len(rows) > height {
		rows = rows[:height]
	}
	return ansi.Strip(strings.Join(rows, "\n"))
}

var fixedViewTestTime = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

func readyModelForViewTest(t *testing.T, width, height int) Model {
	t.Helper()

	m := NewModel(nil, 100, "test", 0)
	m.scheme = deterministicViewTestScheme()
	m = updateModelForViewTest(t, m, tea.WindowSizeMsg{Width: width, Height: height})
	m = updateModelForViewTest(t, m, splashDoneMsg{})
	return m
}

func updateModelForViewTest(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()

	updated, _ := m.Update(msg)
	model, ok := updated.(Model)
	if !ok {
		t.Fatalf("Update(%T) returned %T, want tui.Model", msg, updated)
	}
	return model
}

func renderViewWithoutPanic(t *testing.T, m Model) (out string) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Model.View panicked for active tab %v at width %d: %v", m.activeTab, m.width, r)
		}
	}()
	return m.View()
}

func attemptsForViewTest(count, offset int) BatchAttemptMsg {
	attempts := make(BatchAttemptMsg, 0, count)
	for i := range count {
		attempts = append(attempts, attemptForViewTest(offset+i, false))
	}
	return attempts
}

func attemptForViewTest(i int, success bool) AttemptResultMsg {
	return AttemptResultMsg{
		Host:      fmt.Sprintf("10.0.0.%d", i%250+1),
		Port:      22,
		Service:   "ssh",
		User:      fmt.Sprintf("root%d", i),
		Password:  fmt.Sprintf("pass%d", i),
		Success:   success,
		Connected: success,
		Duration:  time.Duration(i+1) * time.Millisecond,
		Timestamp: fixedViewTestTime.Add(time.Duration(i) * time.Second),
	}
}

func deterministicViewTestScheme() ColorScheme {
	return ColorScheme{
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
