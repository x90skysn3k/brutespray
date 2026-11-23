package brutespray

import (
	"os"
	"path/filepath"
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
	if len(attempts) != 6 {
		t.Fatalf("captured attempts = %d, want 6", len(attempts))
	}
	retried := 0
	skipped := 0
	for _, a := range attempts {
		if a.Retrying {
			retried++
		}
		if a.Status == string(brute.StatusSkippedService) {
			skipped++
		}
	}
	if retried != 0 {
		t.Fatalf("tripped host must not run the missed-credential retry pass, got %d retried attempts", retried)
	}
	if skipped == 0 {
		t.Fatal("expected locally-skipped attempts after the breaker tripped")
	}
	if !cb.IsTripped(hostKey) {
		t.Fatal("breaker should be tripped after 3 connection failures")
	}
}
