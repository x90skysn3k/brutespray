package modules

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDebugAuditRedactsPassword(t *testing.T) {
	path := t.TempDir() + "/debug.jsonl"
	if err := ConfigureDebugAudit(true, path); err != nil {
		t.Fatalf("ConfigureDebugAudit: %v", err)
	}
	t.Cleanup(func() { _ = CloseDebugAudit() })

	WriteDebugAttempt("ssh", "127.0.0.1", 22, "root", "super-secret", "auth_failure", true, false, 25*time.Millisecond, errors.New("root failed with super-secret"))
	if err := CloseDebugAudit(); err != nil {
		t.Fatalf("CloseDebugAudit: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "super-secret") {
		t.Fatalf("debug audit leaked password: %s", out)
	}
	if !strings.Contains(out, "\"password\":\"<redacted>\"") {
		t.Fatalf("debug audit missing redacted password marker: %s", out)
	}
	if !strings.Contains(out, "\"status\":\"auth_failure\"") {
		t.Fatalf("debug audit missing status: %s", out)
	}
}
