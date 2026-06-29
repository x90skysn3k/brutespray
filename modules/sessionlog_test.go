package modules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionLogPersistsAttemptStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	log, err := NewSessionLog(path)
	if err != nil {
		t.Fatalf("NewSessionLog: %v", err)
	}
	log.Write(SessionEntry{
		Type:      "attempt",
		Host:      "127.0.0.1",
		Port:      22,
		Service:   "ssh",
		User:      "root",
		Password:  "toor",
		Status:    "auth_failure",
		Timestamp: time.Now(),
	})
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := LoadSessionLog(path)
	if err != nil {
		t.Fatalf("LoadSessionLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Status != "auth_failure" {
		t.Fatalf("Status = %q, want auth_failure", entries[0].Status)
	}
}

func TestSessionLogUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	log, err := NewSessionLog(path)
	if err != nil {
		t.Fatalf("NewSessionLog: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("session log permissions = %o, want 600", got)
	}
}
