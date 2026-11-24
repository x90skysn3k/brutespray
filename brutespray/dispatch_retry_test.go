package brutespray

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// Issue #366: after all attempts finished, a tripped host was re-hammered by
// the missed-credential retry pass ("it just keeps the server busy at a
// pointless host"). Credentials the breaker skipped locally were also queued
// for retry even though they never touched the network.
func TestProcessHostTrippedHostSkipsRetryPass(t *testing.T) {
	const service = "stormtest"
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: os.ErrDeadlineExceeded}
	})

	cb := brute.GetCircuitBreaker()
	hostKey := "127.0.0.1:1"
	cb.Reset(hostKey)
	cb.SetThreshold(3)
	cb.SetDisabled(false)
	defer func() {
		cb.Reset(hostKey)
		cb.SetThreshold(brute.DefaultCircuitBreakerThreshold)
		cb.SetDisabled(false)
	}()

	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(pwFile, []byte("p1\np2\np3\np4\np5\np6\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cm, err := modules.NewConnectionManager("", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 1, 1)
	wp.noStats = true
	host := modules.Host{Service: service, Host: "127.0.0.1", Port: 1}

	wp.ProcessHost(host, service, "", "u", pwFile, version, 10*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)

	attempts := sink.attemptResults()
	// Threshold 3 with per-credential dial admission: exactly 3 real
	// connection failures, then the remaining credentials drain silently
	// (no phantom CONN ERR rows — issue #366 report 2026-11-23).
	if len(attempts) != 3 {
		t.Fatalf("captured attempts = %d, want 3 (post-trip credentials must not emit events)", len(attempts))
	}
	retried := 0
	for _, a := range attempts {
		if a.Retrying {
			retried++
		}
		if a.Status == string(brute.StatusSkippedService) {
			t.Fatalf("post-trip attempts must not be emitted at all, got skipped event for %s", a.Password)
		}
	}
	if retried != 0 {
		t.Fatalf("tripped host must not run the missed-credential retry pass, got %d retried attempts", retried)
	}
	if !cb.IsTripped(hostKey) {
		t.Fatal("breaker should be tripped after 3 connection failures")
	}
}

// Issue #366 (report 2026-11-23): -max-conn-fails 10 with default/excess
// threads against dead RDP hosts still produced 150-230 CONN ERR rows per
// host and then the retry pass replayed them all. End-to-end contract at
// the dispatch seam: a dead host gets AT MOST `threshold` real connection
// failures regardless of per-host threads, emits no retry pass, and the
// host completes without replaying queued credentials.
func TestProcessHostConnFailsBoundedByThresholdUnderConcurrency(t *testing.T) {
	const (
		service   = "stormtest-dialbudget"
		hostKey   = "127.0.0.1:2"
		threshold = 10
		threads   = 30
		creds     = 200
	)
	var calls atomic.Int64
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond) // overlap the workers
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: os.ErrDeadlineExceeded}
	})

	cb := brute.GetCircuitBreaker()
	origThreshold := cb.GetThreshold()
	origDisabled := cb.IsDisabled()
	cb.Reset(hostKey)
	cb.SetThreshold(threshold)
	cb.SetDisabled(false) // budget gate must be active regardless of suite order
	defer func() {
		cb.Reset(hostKey)
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}()

	lines := make([]string, creds)
	for i := range lines {
		lines[i] = "p" + string(rune('A'+i/26)) + string(rune('a'+i%26)) + string(rune('0'+i%10))
	}
	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(pwFile, []byte(joinLinesForTest(lines)), 0o600); err != nil {
		t.Fatal(err)
	}

	cm, err := modules.NewConnectionManager("", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(threads, sink, 1, 1)
	wp.noStats = true
	host := modules.Host{Service: service, Host: "127.0.0.1", Port: 2}

	wp.ProcessHost(host, service, "", "u", pwFile, version, 50*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)

	if got := calls.Load(); got > int64(threshold) {
		t.Fatalf("real dials = %d, must be <= -max-conn-fails %d regardless of %d threads", got, threshold, threads)
	}
	if !cb.IsTripped(hostKey) {
		t.Fatal("breaker must be tripped after threshold connection failures")
	}

	connErr, skipped, retried := 0, 0, 0
	for _, a := range sink.attemptResults() {
		switch a.Status {
		case string(brute.StatusConnectionFailure):
			connErr++
		case string(brute.StatusSkippedService):
			skipped++
		}
		if a.Retrying {
			retried++
		}
	}
	if connErr > threshold {
		t.Fatalf("connection-error events = %d, must be <= threshold %d", connErr, threshold)
	}
	if int64(connErr) > calls.Load() {
		t.Fatalf("connection-error events (%d) exceed real dials (%d): phantom CONN ERR rows", connErr, calls.Load())
	}
	if retried != 0 {
		t.Fatalf("tripped host must not run the missed-credential retry pass, got %d retried attempts", retried)
	}
	// Post-trip work may surface at most once per in-flight worker, and the
	// whole host must finish long before all 200 credentials are attempted.
	if connErr+skipped >= creds {
		t.Fatalf("host consumed %d/%d credentials; tripped host must abort early", connErr+skipped, creds)
	}
}

func joinLinesForTest(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
