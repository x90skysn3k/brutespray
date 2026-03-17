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
