package tui

// EventSink is the interface that bridges worker goroutines and the UI layer.
// Workers call Send() with structured messages; the UI layer consumes them.
type EventSink interface {
	Send(msg interface{})
	Close()
}

// LegacyEventSink adapts the EventSink interface to the old progressCh-based
// progress tracking. It increments a progress counter for each attempt result.
type LegacyEventSink struct {
	progressCh chan int
}

// NewLegacyEventSink creates an EventSink that forwards progress increments
// to the given channel for use with StartProgressTracker.
func NewLegacyEventSink(progressCh chan int) *LegacyEventSink {
	return &LegacyEventSink{progressCh: progressCh}
}

// Send receives a message from a worker. For legacy mode, it increments
// the progress counter regardless of message type.
func (l *LegacyEventSink) Send(msg interface{}) {
	switch msg.(type) {
	case AttemptResultMsg:
		// Panic-safe send: progressCh may be closed during shutdown.
		func() {
			defer func() { _ = recover() }()
			l.progressCh <- 1
		}()
	}
}

// Close closes the underlying progress channel.
func (l *LegacyEventSink) Close() {
	close(l.progressCh)
}

// ProgressCh returns the underlying channel for use with StartProgressTracker.
func (l *LegacyEventSink) ProgressCh() <-chan int {
	return l.progressCh
}
