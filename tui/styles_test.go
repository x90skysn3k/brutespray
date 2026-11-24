package tui

import "testing"

// Issue #366 (report 2026-11-23): post-trip skipped credentials rendered as
// red "CONN ERR" in every attempt view, so a host the skip policy had
// already given up on looked like it was "still bruting". Skipped attempts
// must carry their own muted SKIPPED label.
func TestAttemptStyleLabelsSkippedService(t *testing.T) {
	cs := NewRandomColorScheme()

	_, status := cs.AttemptStyle(false, false, false, "skipped_service")
	if status != "SKIPPED" {
		t.Fatalf("skipped_service label = %q, want SKIPPED", status)
	}

	// A genuine connection failure keeps the red CONN ERR label.
	if _, status := cs.AttemptStyle(false, false, false, "connection_failure"); status != "CONN ERR" {
		t.Fatalf("connection_failure label = %q, want CONN ERR", status)
	}

	// Legacy behavior for messages with no status set (zero value): the
	// booleans still decide, unchanged from before the status arrived.
	if _, status := cs.AttemptStyle(false, false, false, ""); status != "CONN ERR" {
		t.Fatalf("empty-status default label = %q, want CONN ERR", status)
	}
	if _, status := cs.AttemptStyle(true, true, false, "auth_success"); status != "SUCCESS" {
		t.Fatalf("auth_success label = %q, want SUCCESS", status)
	}
}
