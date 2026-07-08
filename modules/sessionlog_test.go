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

func TestLoadSessionLogSkipsMalformedJSONLLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	data := []byte(
		`{"type":"attempt","host":"127.0.0.1","port":22,"service":"ssh","status":"auth_failure"}` + "\n" +
			`{"type":"attempt","host":` + "\n" +
			`{"type":"attempt","host":"127.0.0.2","port":80,"service":"http","status":"success"}` + "\n",
	)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session log: %v", err)
	}

	entries, err := LoadSessionLog(path)
	if err != nil {
		t.Fatalf("LoadSessionLog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Host != "127.0.0.1" || entries[0].Status != "auth_failure" {
		t.Fatalf("first entry = %+v, want 127.0.0.1 auth_failure", entries[0])
	}
	if entries[1].Host != "127.0.0.2" || entries[1].Status != "success" {
		t.Fatalf("second entry = %+v, want 127.0.0.2 success", entries[1])
	}
}
