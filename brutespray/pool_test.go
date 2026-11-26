package brutespray

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

// noopEventSink discards all events.
type noopEventSink struct{}

func (noopEventSink) Send(msg interface{}) {}
func (noopEventSink) Close()               {}

var _ tui.EventSink = noopEventSink{}

// mockBruteResult is the result returned by the test-pool-service module.
var mockBruteResult atomic.Value // *brute.BruteResult

func init() {
	// Set default result
	mockBruteResult.Store(&brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true})

	brute.Register("test-pool-service", func(host string, port int, user, password string,
		timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		result := mockBruteResult.Load().(*brute.BruteResult)
		return &brute.BruteResult{
			AuthSuccess:       result.AuthSuccess,
			ConnectionSuccess: result.ConnectionSuccess,
			Error:             result.Error,
			SkipUser:          result.SkipUser,
		}
	})
}

func setMockResult(r *brute.BruteResult) {
	mockBruteResult.Store(r)
}

func TestHostWorkerPoolBasicLifecycle(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9999, Service: "test-pool-service"}
	sink := noopEventSink{}
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	setMockResult(&brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true})

	hwp := NewHostWorkerPool(host, 1, sink, false, 0)
	hwp.Start(1*time.Second, 1, "", cm, "", true)

	// Queue some credentials
	for i := 0; i < 5; i++ {
		hwp.jobQueue <- Credential{
			Host:     host,
			User:     "user",
			Password: "pass",
			Service:  "test-pool-service",
		}
	}

	close(hwp.jobQueue)
	hwp.wg.Wait()

	// Verify workers processed credentials (pool completed without hanging)
	hwp.mutex.RLock()
	attempts := hwp.totalAttempts
	hwp.mutex.RUnlock()
	if attempts != 5 {
		t.Fatalf("expected 5 attempts, got %d", attempts)
	}
}

func TestHostWorkerPoolStopOnSuccess(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9998, Service: "test-pool-service"}
	sink := noopEventSink{}
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	setMockResult(&brute.BruteResult{AuthSuccess: true, ConnectionSuccess: true})
	// The mock accepts every password, which is exactly what the
	// any-password confirmation probe demotes. This test targets
	// stop-on-success semantics, so turn the probe off.
	defer func(orig bool) { brute.ConfirmAnyPassword = orig }(brute.ConfirmAnyPassword)
	brute.ConfirmAnyPassword = false

	hwp := NewHostWorkerPool(host, 1, sink, true, 0) // stopOnSuccess=true
	hwp.Start(1*time.Second, 1, "", cm, "", true)

	// Queue a credential that will succeed
	hwp.jobQueue <- Credential{
		Host:     host,
		User:     "user",
		Password: "pass",
		Service:  "test-pool-service",
	}

	// Wait for the worker to process (jitter up to 100ms with 1s timeout)
	time.Sleep(2 * time.Second)

	// stopChan should be closed after success
	select {
	case <-hwp.stopChan:
		// expected
	default:
		t.Fatal("expected stopChan to be closed after auth success with stopOnSuccess=true")
	}

	if atomic.LoadInt32(&hwp.foundSuccess) != 1 {
		t.Fatal("expected foundSuccess to be set")
	}

	close(hwp.jobQueue)
	hwp.wg.Wait()
}

func TestHostWorkerPoolSkipUser(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9997, Service: "test-pool-service"}
	sink := noopEventSink{}
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	setMockResult(&brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true, SkipUser: true})

	hwp := NewHostWorkerPool(host, 1, sink, false, 0)
	hwp.Start(1*time.Second, 1, "", cm, "", true)

	// Queue a credential that triggers SkipUser
	hwp.jobQueue <- Credential{
		Host:     host,
		User:     "skipme",
		Password: "pass1",
		Service:  "test-pool-service",
	}

	// Wait for processing (jitter up to 100ms with 1s timeout, plus RunBrute time)
	time.Sleep(2 * time.Second)

	// After first attempt, "skipme" should be in skipUsers
	_, skipped := hwp.skipUsers.Load("skipme")
	if !skipped {
		t.Fatal("expected 'skipme' to be in skipUsers map")
	}

	// Now switch to non-skip result and queue another cred for same user
	setMockResult(&brute.BruteResult{AuthSuccess: true, ConnectionSuccess: true})
	hwp.jobQueue <- Credential{
		Host:     host,
		User:     "skipme",
		Password: "pass2",
		Service:  "test-pool-service",
	}

	time.Sleep(1 * time.Second)
	close(hwp.jobQueue)
	hwp.wg.Wait()

	// Only 1 attempt should have been processed (second was skipped)
	hwp.mutex.RLock()
	attempts := hwp.totalAttempts
	hwp.mutex.RUnlock()
	if attempts != 1 {
		t.Fatalf("expected 1 attempt (second should be skipped), got %d", attempts)
	}
}

func TestHostWorkerPoolResetForRetry(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9996, Service: "test-pool-service"}
	sink := noopEventSink{}

	hwp := NewHostWorkerPool(host, 2, sink, true, 0)

	// Simulate a completed pool with success
	atomic.StoreInt32(&hwp.foundSuccess, 1)
	hwp.stopOnce.Do(func() { close(hwp.stopChan) })
	hwp.skipUsers.Store("someuser", struct{}{})
	atomic.StoreInt64(&hwp.consecutiveConnFails, 5)

	// Reset
	hwp.ResetForRetry()

	if atomic.LoadInt32(&hwp.foundSuccess) != 0 {
		t.Fatal("foundSuccess should be reset to 0")
	}
	if atomic.LoadInt32(&hwp.currentWorkers) != 0 {
		t.Fatal("currentWorkers should be reset to 0")
	}
	if atomic.LoadInt64(&hwp.consecutiveConnFails) != 0 {
		t.Fatal("consecutiveConnFails should be reset to 0")
	}
	if _, found := hwp.skipUsers.Load("someuser"); found {
		t.Fatal("skipUsers should be cleared")
	}

	// Verify stopChan is open (not closed)
	select {
	case <-hwp.stopChan:
		t.Fatal("stopChan should be open after reset")
	default:
		// expected
	}
}

func TestHostWorkerPoolPauseResume(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9995, Service: "test-pool-service"}
	sink := noopEventSink{}
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	setMockResult(&brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true})

	hwp := NewHostWorkerPool(host, 1, sink, false, 0)

	// Pause before starting
	hwp.Pause()

	hwp.Start(1*time.Second, 1, "", cm, "", true)

	// Queue a credential
	go func() {
		hwp.jobQueue <- Credential{
			Host:     host,
			User:     "user",
			Password: "pass",
			Service:  "test-pool-service",
		}
	}()

	// Give workers time to hit the pause point
	time.Sleep(500 * time.Millisecond)

	hwp.mutex.RLock()
	processedCount := hwp.totalAttempts
	hwp.mutex.RUnlock()

	if processedCount != 0 {
		t.Fatal("expected 0 attempts while paused")
	}

	// Resume
	hwp.Resume()

	// Wait for processing (jitter up to 100ms + processing time)
	time.Sleep(2 * time.Second)

	hwp.mutex.RLock()
	processedCount = hwp.totalAttempts
	hwp.mutex.RUnlock()

	if processedCount != 1 {
		t.Fatalf("expected 1 attempt after resume, got %d", processedCount)
	}

	close(hwp.jobQueue)
	hwp.wg.Wait()
}

// Issue #366 (PR #374): the adaptive pre-dial backoff must apply ONLY when
// the circuit breaker is disabled. With the breaker enabled, failure-budget
// admission (AdmitDial) is the pacing — the sleep would stack on top and
// make the skip threshold unreachable (~3 min for 10 failures at fails>=5).
// With `-skip-policy off` (breaker disabled) the legacy wait must survive
// and stay cancelable via the host stop channel.
func TestApplyAdaptiveBackoffOnlyWhenBreakerDisabled(t *testing.T) {
	enabledHost := modules.Host{Host: "127.0.0.1", Port: 9996, Service: "test-pool-service"}
	disabledHost := modules.Host{Host: "127.0.0.1", Port: 9997, Service: "test-pool-service"}
	cb := brute.GetCircuitBreaker()
	origDisabled := cb.IsDisabled()
	defer func() { cb.SetDisabled(origDisabled) }()

	newPool := func(host modules.Host, fails int64) *HostWorkerPool {
		hwp := NewHostWorkerPool(host, 1, noopEventSink{}, false, 0)
		atomic.StoreInt64(&hwp.consecutiveConnFails, fails)
		return hwp
	}

	// Enabled breaker: budget admission paces; the sleep must be skipped.
	cb.SetDisabled(false)
	hwp := newPool(enabledHost, 9) // legacy backoff would sleep 30s
	start := time.Now()
	if stopped := hwp.applyAdaptiveBackoff(Credential{Host: enabledHost}); stopped {
		t.Fatal("enabled breaker must not report stop")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("enabled breaker bypassed sleep expectation: applyAdaptiveBackoff waited %v", elapsed)
	}

	// Disabled breaker (skip-policy off): legacy wait applies. fails=1 →
	// legacy sleep is 2s, so this branch is bounded and still proves the
	// wait survives (a bypass would return in <500ms like the case above).
	cb.SetDisabled(true)
	hwp = newPool(disabledHost, 1)
	start = time.Now()
	if stopped := hwp.applyAdaptiveBackoff(Credential{Host: disabledHost}); stopped {
		t.Fatal("backoff must complete, not report stop, when nothing cancels it")
	}
	if elapsed := time.Since(start); elapsed < 1*time.Second {
		t.Fatalf("disabled breaker must still wait (legacy backoff), waited only %v", elapsed)
	}

	// ...and stays cancelable via stopChan.
	close(hwp.stopChan)
	atomic.StoreInt64(&hwp.consecutiveConnFails, 9) // would sleep 30s uncancelled
	start = time.Now()
	if stopped := hwp.applyAdaptiveBackoff(Credential{Host: disabledHost}); !stopped {
		t.Fatal("backoff must report stop when stopChan is closed")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancelled backoff took %v, must return promptly", elapsed)
	}
}

// Issue #378 lifecycle race: completed host pools stayed eligible for the
// 2-second dynamic scaler, which could wg.Add workers onto a pool whose
// jobQueue was already closed and whose wg.Wait was already running
// (WaitGroup misuse / phantom activity after a host finished). The
// terminal flag — set under the same mutex as every wg.Add — must make
// Start/scaleTo inert, and ResetForRetry must atomically hand the pool a
// fresh queue so no tick can spawn onto the closed one.
func TestScalerCannotReviveTerminalPool(t *testing.T) {
	host := modules.Host{Host: "127.0.0.1", Port: 9997, Service: "test-pool-service"}
	sink := noopEventSink{}
	cm, _ := modules.NewConnectionManager("", 1*time.Second)
	setMockResult(&brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true})

	hwp := NewHostWorkerPool(host, 1, sink, false, 0)
	hwp.Start(1*time.Second, 1, "", cm, "", true)
	for range 2 {
		hwp.jobQueue <- Credential{Host: host, User: "u", Password: "p", Service: "test-pool-service"}
	}
	hwp.markTerminal()
	close(hwp.jobQueue)
	hwp.wg.Wait()

	// Post-completion scaler ticks must be inert.
	hwp.scaleTo(8, 1*time.Second, 1, "", cm, "", true)
	hwp.Start(1*time.Second, 1, "", cm, "", true)
	if n := atomic.LoadInt32(&hwp.currentWorkers); n != 0 {
		t.Fatalf("currentWorkers = %d after terminal, want 0 (scaler revived a completed pool)", n)
	}
	hwp.wg.Wait() // must return immediately: no phantom Adds

	// ResetForRetry installs the fresh queue atomically with clearing the
	// terminal flag, so the pool is immediately usable for a retry pass.
	hwp.ResetForRetry()
	hwp.Start(1*time.Second, 1, "", cm, "", true)
	select {
	case hwp.jobQueue <- Credential{Host: host, User: "u", Password: "p2", Service: "test-pool-service"}:
	default:
		t.Fatal("job queue after ResetForRetry not usable")
	}
	hwp.markTerminal()
	close(hwp.jobQueue)
	hwp.wg.Wait()

	hwp.mutex.RLock()
	attempts := hwp.totalAttempts
	hwp.mutex.RUnlock()
	if attempts != 3 {
		t.Fatalf("total attempts = %d, want 3 (2 main pass + 1 retry)", attempts)
	}
}
