package brutespray

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// Issue #378: after conn-failed hosts were skipped, work kept starting for
// targets that were already done. Duplicate identical targets in cfg.Hosts
// (e.g. the same service://host:port repeated with -H, or overlapping -f and
// -H inputs) launch concurrent ProcessHost calls for the same host:port.
// All host goroutines start at once and the checkpoint/completion check runs
// BEFORE the host semaphore, so both duplicates can pass it and drive one
// shared HostWorkerPool: two Start() calls double the workers, both feed one
// jobQueue, and both hit close(jobQueue) — a double close on the same queue
// (panic when the first close has already happened while the second is
// queued; at best every credential is brute-forced twice).

func writeWordlist(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pw.txt")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestProcessHostConcurrentDuplicatesDoNotShareQueue asserts two concurrent
// ProcessHost calls for the SAME exact target neither panic (queue double
// close) nor run every credential twice.
func TestProcessHostConcurrentDuplicatesDoNotShareQueue(t *testing.T) {
	const service = "dupconv"
	var calls atomic.Int64
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		calls.Add(1)
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	cb := brute.GetCircuitBreaker()
	origThreshold, origDisabled := cb.GetThreshold(), cb.IsDisabled()
	hostKey := "127.0.0.1:45001"
	cb.Reset(hostKey)
	defer func() {
		cb.Reset(hostKey)
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}()

	pwFile := writeWordlist(t, "p1", "p2", "p3", "p4")
	cm, err := modules.NewConnectionManager("", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(2, sink, 4, 2)
	wp.noStats = true
	host := modules.Host{Service: service, Host: "127.0.0.1", Port: 45001}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Recover so a queue double-close surfaces as a test failure
			// instead of killing the whole package run.
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("duplicate ProcessHost panicked: %v", r)
				}
			}()
			wp.ProcessHost(host, service, "", "u", pwFile, version, 100*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)
		}()
	}
	wg.Wait()

	// Correct behavior: the duplicate target does no second pass — exactly
	// 4 module calls total, once per credential.
	if got := calls.Load(); got != 4 {
		t.Fatalf("module calls = %d, want exactly 4 (duplicate target must not re-brute the same host)", got)
	}
}

// TestProcessHostSequentialDuplicateDoesNotRebrute asserts a second
// ProcessHost for an already-completed same-target call is a pure no-op:
// no credential re-run AND no second HostStartedMsg/HostCompletedMsg — the
// phantom lifecycle is exactly what made skipped hosts look like they were
// starting new work (issue #378).
func TestProcessHostSequentialDuplicateDoesNotRebrute(t *testing.T) {
	const service = "dupseq"
	var calls atomic.Int64
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		calls.Add(1)
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	cb := brute.GetCircuitBreaker()
	origThreshold, origDisabled := cb.GetThreshold(), cb.IsDisabled()
	hostKey := "127.0.0.1:45002"
	cb.Reset(hostKey)
	defer func() {
		cb.Reset(hostKey)
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}()

	pwFile := writeWordlist(t, "p1", "p2")
	cm, err := modules.NewConnectionManager("", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 1, 1)
	wp.noStats = true
	host := modules.Host{Service: service, Host: "127.0.0.1", Port: 45002}

	done := func() {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("duplicate ProcessHost panicked: %v", r)
			}
		}()
		wp.ProcessHost(host, service, "", "u", pwFile, version, 100*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)
	}
	done() // first pass: 2 credentials
	first := calls.Load()
	done() // duplicate target: must be a no-op

	if first != 2 {
		t.Fatalf("first pass calls = %d, want 2", first)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("total calls after duplicate = %d, want 2 (duplicate must not re-brute)", got)
	}
	started, completed := sink.lifecycle()
	if started != 1 || completed != 1 {
		t.Fatalf("lifecycle events = started %d, completed %d; want 1/1 (duplicate target must not emit a phantom lifecycle)", started, completed)
	}
}

// TestProcessHostSameHostPortDifferentServicesBothRun asserts two different
// services on the same host:port get independent worker pools: the old
// host:port-only pool key made them share one jobQueue, so the second
// service fed (or closed) a queue owned by the first — a double close or a
// silently dropped service.
func TestProcessHostSameHostPortDifferentServicesBothRun(t *testing.T) {
	const (
		serviceA = "dupsvc-a"
		serviceB = "dupsvc-b"
	)
	var callsA, callsB atomic.Int64
	noop := func(counter *atomic.Int64) brute.BruteFunc {
		return func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
			counter.Add(1)
			return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
	}
	brute.Register(serviceA, noop(&callsA))
	brute.Register(serviceB, noop(&callsB))

	cb := brute.GetCircuitBreaker()
	origThreshold, origDisabled := cb.GetThreshold(), cb.IsDisabled()
	hostKey := "127.0.0.1:45003"
	cb.Reset(hostKey)
	defer func() {
		cb.Reset(hostKey)
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}()

	pwFile := writeWordlist(t, "p1", "p2")
	cm, err := modules.NewConnectionManager("", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 2, 2)
	wp.noStats = true
	hostA := modules.Host{Service: serviceA, Host: "127.0.0.1", Port: 45003}
	hostB := modules.Host{Service: serviceB, Host: "127.0.0.1", Port: 45003}

	var wg sync.WaitGroup
	for _, h := range []modules.Host{hostA, hostB} {
		wg.Add(1)
		go func(host modules.Host) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ProcessHost(%s) panicked: %v", host.Service, r)
				}
			}()
			wp.ProcessHost(host, host.Service, "", "u", pwFile, version, 100*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)
		}(h)
	}
	wg.Wait()

	if got := callsA.Load(); got != 2 {
		t.Fatalf("%s calls = %d, want 2", serviceA, got)
	}
	if got := callsB.Load(); got != 2 {
		t.Fatalf("%s calls = %d, want 2 (second service on same host:port was dropped or corrupted)", serviceB, got)
	}
}

// TestDedupeHosts pins the config-level canonical dedup: exact duplicate
// targets are collapsed to one entry, first-seen order preserved, and a
// same host:port with a different service is NOT collapsed.
func TestDedupeHosts(t *testing.T) {
	in := []modules.Host{
		{Service: "ssh", Host: "10.0.0.1", Port: 22},
		{Service: "http", Host: "10.0.0.2", Port: 80},
		{Service: "ssh", Host: "10.0.0.1", Port: 22},   // duplicate of first
		{Service: "https", Host: "10.0.0.2", Port: 80}, // same host:port, other service
	}
	out := dedupeHosts(in)
	if len(out) != 3 {
		t.Fatalf("dedupeHosts len = %d, want 3: %+v", len(out), out)
	}
	if out[0].Service != "ssh" || out[1].Service != "http" || out[2].Service != "https" {
		t.Fatalf("dedupeHosts changed order/content: %+v", out)
	}
}
