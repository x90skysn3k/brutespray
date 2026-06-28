package brutespray

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

func TestResumeCursorSkipsAttemptedPrefix(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 22, Service: "ssh"}
	cp := modules.NewCheckpoint("")
	cp.RecordAttemptForHost(host.Host, host.Port, host.Service)
	cp.RecordAttemptForHost(host.Host, host.Port, host.Service)

	cursor := newResumeCursor(cp, host)
	got := []bool{cursor.skipNext(), cursor.skipNext(), cursor.skipNext()}
	want := []bool{true, true, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("skip[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestResumeCursorNilCheckpointDoesNotSkip(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 22, Service: "ssh"}
	cursor := newResumeCursor(nil, host)
	if cursor.skipNext() {
		t.Fatal("nil checkpoint should not skip credentials")
	}
}

func TestProcessCredentialRecordsCheckpointAttempt(t *testing.T) {
	service := "checkpoint-record-test"
	brute.Register(service, func(string, int, string, string, time.Duration, *modules.ConnectionManager, brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	host := modules.Host{Host: "127.0.0.1", Port: 22, Service: service}
	cp := modules.NewCheckpoint("")
	progressCh := make(chan tui.ProgressEvent, 10)
	hwp := NewHostWorkerPool(host, 1, tui.NewLegacyEventSink(progressCh), false, 0)
	hwp.checkpoint = cp
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	hwp.processCredential(Credential{Host: host, User: "u", Password: "p", Service: service}, time.Second, 1, t.TempDir(), cm, "", false)
	if got := cp.GetAttemptedCount(host.Host, host.Port, host.Service); got != 1 {
		t.Fatalf("attempted count = %d, want 1", got)
	}

	hwp.processCredential(Credential{Host: host, User: "u", Password: "p", Service: service, Retry: true}, time.Second, 1, t.TempDir(), cm, "", false)
	if got := cp.GetAttemptedCount(host.Host, host.Port, host.Service); got != 1 {
		t.Fatalf("attempted count after retry = %d, want 1", got)
	}
}

func TestProcessCredentialWritesDebugAudit(t *testing.T) {
	service := "checkpoint-debug-audit-test"
	brute.Register(service, func(string, int, string, string, time.Duration, *modules.ConnectionManager, brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	path := t.TempDir() + "/debug.jsonl"
	if err := modules.ConfigureDebugAudit(true, path); err != nil {
		t.Fatalf("ConfigureDebugAudit: %v", err)
	}
	t.Cleanup(func() { _ = modules.CloseDebugAudit() })

	host := modules.Host{Host: "127.0.0.1", Port: 22, Service: service}
	progressCh := make(chan tui.ProgressEvent, 10)
	hwp := NewHostWorkerPool(host, 1, tui.NewLegacyEventSink(progressCh), false, 0)
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	hwp.processCredential(Credential{Host: host, User: "u", Password: "super-secret", Service: service}, time.Second, 1, t.TempDir(), cm, "", false)
	if err := modules.CloseDebugAudit(); err != nil {
		t.Fatalf("CloseDebugAudit: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "super-secret") {
		t.Fatalf("worker debug audit leaked password: %s", out)
	}
	if !strings.Contains(out, "\"status\":\"auth_failure\"") {
		t.Fatalf("worker debug audit missing status: %s", out)
	}
}
