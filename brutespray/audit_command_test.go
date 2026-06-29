package brutespray

import (
	"path/filepath"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestAuditCommandVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := modules.NewAuditLog(path)
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

func TestAuditCommandRejectsUnknownSubcommand(t *testing.T) {
	if err := AuditCommand([]string{"nope"}); err == nil {
		t.Fatal("expected error")
	}
}
