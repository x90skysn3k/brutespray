package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointSaveUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	cp := NewCheckpoint(path)
	cp.RecordSuccessForCheckpoint("ssh", "127.0.0.1", 22, "root", "toor")
	if err := cp.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("checkpoint permissions = %o, want 600", got)
	}
}
