package tui

import (
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type burstPool struct{ parallel int }

func (*burstPool) PauseHost(string)      {}
func (*burstPool) ResumeHost(string)     {}
func (*burstPool) PauseAll()             {}
func (*burstPool) ResumeAll()            {}
func (*burstPool) Stop()                 {}
func (*burstPool) SetThreadsPerHost(int) {}
func (p *burstPool) SetHostParallelism(n int) { p.parallel = n }
func (*burstPool) GetThreadsPerHost() int     { return 30 }
func (p *burstPool) GetHostParallelism() int  { return p.parallel }

// bubbletea coalesces runs of printable characters delivered in one read
// into a single KeyRunes message (one "lllll" message, not five "l"
// messages). The key bindings match single characters, so a burst must be
// processed as individual presses — otherwise holding or pasting a nav key
// silently does nothing.
func TestHandleKeyProcessesCoalescedRunesIndividually(t *testing.T) {
	m := NewModel(&burstPool{parallel: 5}, 100, "test", 0)
	var model tea.Model = m
	model, _ = model.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model, _ = model.Update(splashDoneMsg{})

	// Seven coalesced "l" presses = All -> ... -> Settings (index 7).
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("lllllll")})
	mv := model.(Model)
	if mv.activeTab != TabSettings {
		t.Fatalf("activeTab = %d after coalesced 'lllllll', want TabSettings (%d)", mv.activeTab, TabSettings)
	}
	if !strings.Contains(mv.View(), "Settings & Stats") {
		t.Fatal("Settings view did not render after coalesced tab presses")
	}

	// "jj": focus content, then move to the second (editable) field.
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("jj")})
	mv = model.(Model)
	if mv.tabBarFocused {
		t.Fatal("coalesced 'jj' did not move focus into content")
	}
	// "hh": AdjustLeft on Parallel Hosts twice.
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("hh")})
	view := model.(Model).View()
	if !regexp.MustCompile(`Parallel Hosts.*◀\s*3\s*▶`).MatchString(view) {
		t.Fatalf("coalesced 'hh' did not decrement Parallel Hosts twice; view:\n%s", view)
	}
}
