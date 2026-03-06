package tui

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// SendError sends an error message to the TUI for display.
func (eb *EventBus) SendError(msg string) {
	if eb.closed.Load() || eb.program == nil {
		return
	}
	eb.program.Send(ErrorMsg{
		Message:   msg,
		Timestamp: time.Now(),
	})
}

// EventBus batches incoming worker events and flushes them to the
// Bubble Tea program periodically, preventing per-message re-renders.
type EventBus struct {
	program *tea.Program
	closed  atomic.Bool

	mu       sync.Mutex
	attempts []AttemptResultMsg
	other    []interface{} // HostStartedMsg, HostCompletedMsg, etc.

	stopCh chan struct{}
}

// NewEventBus creates an EventBus. Call SetProgram after tea.NewProgram.
func NewEventBus() *EventBus {
	return &EventBus{
		stopCh: make(chan struct{}),
	}
}

// SetProgram sets the tea.Program reference and starts the flush loop.
func (eb *EventBus) SetProgram(p *tea.Program) {
	eb.program = p
	go eb.flushLoop()
}

// flushLoop sends batched messages to the program every 200ms.
func (eb *EventBus) flushLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			eb.flush()
		case <-eb.stopCh:
			eb.flush() // final flush
			return
		}
	}
}

func (eb *EventBus) flush() {
	if eb.program == nil {
		return
	}

	eb.mu.Lock()
	attempts := eb.attempts
	other := eb.other
	eb.attempts = nil
	eb.other = nil
	eb.mu.Unlock()

	// Send non-attempt messages first (host started/completed)
	for _, msg := range other {
		eb.program.Send(msg)
	}

	// Send attempts as a single batch
	if len(attempts) > 0 {
		eb.program.Send(BatchAttemptMsg(attempts))
	}
}

// Send queues a message for batched delivery.
// Safe to call from any goroutine.
func (eb *EventBus) Send(msg interface{}) {
	if eb.closed.Load() {
		return
	}

	eb.mu.Lock()
	switch m := msg.(type) {
	case AttemptResultMsg:
		eb.attempts = append(eb.attempts, m)
	default:
		eb.other = append(eb.other, msg)
	}
	eb.mu.Unlock()
}

// Close stops the flush loop and marks the bus as closed.
func (eb *EventBus) Close() {
	if eb.closed.CompareAndSwap(false, true) {
		close(eb.stopCh)
	}
}

// Run starts the interactive TUI. It blocks until the user exits.
// If replayEntries is non-empty, historical session data is replayed into the TUI.
func Run(pool WorkerPoolController, totalCombinations int, eventBus *EventBus, version string, replayEntries []modules.SessionEntry) error {
	resumedProgress := 0
	for _, e := range replayEntries {
		if e.Type == "attempt" {
			resumedProgress++
		}
	}

	model := NewModel(pool, totalCombinations, version, resumedProgress)

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	eventBus.SetProgram(p)

	// Replay historical entries so the TUI shows the previous session
	if len(replayEntries) > 0 {
		go ReplaySession(eventBus, replayEntries)
	}

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	_ = finalModel
	return nil
}

// ReplaySession sends historical session entries to the TUI via the EventBus.
func ReplaySession(eventBus *EventBus, entries []modules.SessionEntry) {
	for _, e := range entries {
		switch e.Type {
		case "host_started":
			eventBus.Send(HostStartedMsg{
				Host:    e.Host,
				Port:    e.Port,
				Service: e.Service,
				Threads: e.Threads,
			})
		case "attempt":
			eventBus.Send(AttemptResultMsg{
				Host:      e.Host,
				Port:      e.Port,
				Service:   e.Service,
				User:      e.User,
				Password:  e.Password,
				Success:   e.Success,
				Connected: e.Connected,
				Retrying:  e.Retrying,
				Duration:  e.Duration,
				Timestamp: e.Timestamp,
			})
		case "host_completed":
			eventBus.Send(HostCompletedMsg{
				Host:          e.Host,
				Port:          e.Port,
				Service:       e.Service,
				TotalAttempts: e.TotalAttempts,
				SuccessRate:   e.SuccessRate,
				AvgResponseMs: e.AvgResponseMs,
			})
		}
	}
}

// SendDone signals the TUI that all work is complete.
func SendDone(eventBus *EventBus) {
	if eventBus.program != nil {
		eventBus.program.Send(doneMsg{})
	}
}
