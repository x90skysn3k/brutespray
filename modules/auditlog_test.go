package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogHashChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := log.Write(AuditEvent{Type: "run_start", RunID: "run1"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Write(AuditEvent{Type: "run_end", RunID: "run1"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := VerifyAuditLog(path); err != nil {
		t.Fatalf("VerifyAuditLog: %v", err)
	}
}

func TestAuditLogDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := log.Write(AuditEvent{Type: "run_start", RunID: "run1"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[20] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := VerifyAuditLog(path); err == nil {
		t.Fatal("expected tamper verification failure")
	}
}
