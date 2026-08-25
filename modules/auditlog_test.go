package modules

import (
	"os"
	"path/filepath"
	"testing"
)

var testAuditHMACKey = []byte("test-audit-hmac-key")

func TestAuditLogHashChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path, testAuditHMACKey)
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
	if err := VerifyAuditLog(path, testAuditHMACKey); err != nil {
		t.Fatalf("VerifyAuditLog: %v", err)
	}
}

func TestAuditLogDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path, testAuditHMACKey)
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
	if err := VerifyAuditLog(path, testAuditHMACKey); err == nil {
		t.Fatal("expected tamper verification failure")
	}
}

func TestAuditLogRejectsDifferentHMACKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path, testAuditHMACKey)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := log.Write(AuditEvent{Type: "run_start", RunID: "run1"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := VerifyAuditLog(path, []byte("different-key")); err == nil {
		t.Fatal("expected verification with a different HMAC key to fail")
	}
}

func TestAuditLogRequiresHMACKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := NewAuditLog(path, nil); err == nil {
		t.Fatal("expected NewAuditLog without an HMAC key to fail")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := VerifyAuditLog(path, nil); err == nil {
		t.Fatal("expected VerifyAuditLog without an HMAC key to fail")
	}
}
