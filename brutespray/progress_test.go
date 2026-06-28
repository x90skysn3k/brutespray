package brutespray

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/tui"
)

func TestStartProgressTrackerSeparatesRetries(t *testing.T) {
	oldNoColor := NoColorMode
	NoColorMode = true
	t.Cleanup(func() { NoColorMode = oldNoColor })

	progressCh := make(chan tui.ProgressEvent, 3)
	mu, completed, retries := StartProgressTracker(progressCh, 1, 1, nil)

	progressCh <- tui.ProgressEvent{}
	progressCh <- tui.ProgressEvent{Retry: true}
	close(progressCh)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		gotCompleted := *completed
		gotRetries := *retries
		mu.Unlock()
		if gotCompleted == 1 && gotRetries == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if *completed != 1 || *retries != 1 {
		t.Fatalf("completed=%d retries=%d, want completed=1 retries=1", *completed, *retries)
	}
}
