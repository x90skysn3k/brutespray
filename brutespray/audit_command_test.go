package brutespray

import (
	"path/filepath"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestAuditCommandVerify(t *testing.T) {
	const auditKey = "test-audit-hmac-key"
	t.Setenv("BRUTESPRAY_AUDIT_HMAC_KEY", auditKey)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := modules.NewAuditLog(path, []byte(auditKey))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := log.Write(modules.AuditEvent{Type: "run_start", RunID: "run1"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := AuditCommand([]string{"verify", path}); err != nil {
		t.Fatalf("AuditCommand verify: %v", err)
	}
}

func TestAuditCommandVerifyRequiresHMACKey(t *testing.T) {
	t.Setenv("BRUTESPRAY_AUDIT_HMAC_KEY", "")
	if err := AuditCommand([]string{"verify", filepath.Join(t.TempDir(), "audit.jsonl")}); err == nil {
		t.Fatal("expected audit verification without BRUTESPRAY_AUDIT_HMAC_KEY to fail")
	}
}

func TestAuditCommandRejectsUnknownSubcommand(t *testing.T) {
	if err := AuditCommand([]string{"nope"}); err == nil {
		t.Fatal("expected error")
	}
}
