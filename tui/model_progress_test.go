package tui

import "testing"

func TestModelSeparatesRetryProgress(t *testing.T) {
	m := NewModel(nil, 1, "test", 0)
	updated, _ := m.Update(BatchAttemptMsg{
		{Host: "127.0.0.1", Port: 22, Service: "ssh", User: "u", Password: "p", Connected: false},
		{Host: "127.0.0.1", Port: 22, Service: "ssh", User: "u", Password: "p", Connected: false, Retrying: true},
	})
	model := updated.(Model)

	if model.currentProgress != 1 {
		t.Fatalf("currentProgress=%d, want 1", model.currentProgress)
	}
	if model.retryProgress != 1 {
		t.Fatalf("retryProgress=%d, want 1", model.retryProgress)
	}
}
