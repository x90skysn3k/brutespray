package brute

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestCircuitBreakerTripsAfterThreshold(t *testing.T) {
	cb := &CircuitBreaker{
		consecutiveFails: make(map[string]*int64),
		tripped:          make(map[string]bool),
		threshold:        3,
	}

	host := "10.0.0.1:22"

	for i := 0; i < 2; i++ {
		if cb.RecordFailure(host) {
			t.Fatalf("circuit breaker tripped too early at failure %d", i+1)
		}
	}

	if !cb.RecordFailure(host) {
		t.Fatal("circuit breaker should have tripped at threshold")
	}

	if !cb.IsTripped(host) {
		t.Fatal("circuit breaker should report tripped")
	}
}

func TestCircuitBreakerResetOnSuccess(t *testing.T) {
	cb := &CircuitBreaker{
		consecutiveFails: make(map[string]*int64),
		tripped:          make(map[string]bool),
		threshold:        3,
	}

	host := "10.0.0.1:22"

	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordSuccess(host)

	// After reset, should take 3 more failures to trip
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	if cb.IsTripped(host) {
		t.Fatal("circuit breaker should not be tripped after reset + 2 failures")
	}
}

func TestCircuitBreakerIsolatesHosts(t *testing.T) {
	cb := &CircuitBreaker{
		consecutiveFails: make(map[string]*int64),
		tripped:          make(map[string]bool),
		threshold:        2,
	}

	cb.RecordFailure("host1:22")
	cb.RecordFailure("host1:22")

	if !cb.IsTripped("host1:22") {
		t.Fatal("host1 should be tripped")
	}
	if cb.IsTripped("host2:22") {
		t.Fatal("host2 should not be tripped")
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := &CircuitBreaker{
		consecutiveFails: make(map[string]*int64),
		tripped:          make(map[string]bool),
		threshold:        2,
	}

	host := "10.0.0.1:22"
	cb.RecordFailure(host)
	cb.RecordFailure(host)

	cb.Reset(host)

	if cb.IsTripped(host) {
		t.Fatal("circuit breaker should not be tripped after Reset")
	}
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		retry int
		minMs int
		maxMs int
	}{
		{0, 375, 625},    // 500ms ± 25%
		{1, 750, 1250},   // 1000ms ± 25%
		{2, 1500, 2500},  // 2000ms ± 25%
		{10, 3750, 6250}, // capped at 5s ± 25%
	}

	for _, tt := range tests {
		d := calculateBackoff(tt.retry)
		ms := d.Milliseconds()
		if ms < int64(tt.minMs) || ms > int64(tt.maxMs) {
			t.Errorf("calculateBackoff(%d) = %dms, want [%d, %d]ms", tt.retry, ms, tt.minMs, tt.maxMs)
		}
	}
}

func TestCalculateBackoffCap(t *testing.T) {
	// Even at very high retry counts, backoff should not exceed ~6.25s (5s * 1.25 jitter)
	d := calculateBackoff(100)
	if d > 7*time.Second {
		t.Errorf("calculateBackoff(100) = %v, exceeds cap", d)
	}
}

// breakerTestService registers a service that replays the given results in
// attempt order (last result repeats when exhausted) and sets the breaker
// threshold for hostKey. Returns a cleanup func.
func breakerTestService(t *testing.T, service, hostKey string, threshold int64, results ...BruteFunc) func() {
	t.Helper()
	var mu sync.Mutex
	next := 0
	Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		mu.Lock()
		idx := next
		if idx >= len(results) {
			idx = len(results) - 1
		}
		next++
		mu.Unlock()
		return results[idx](host, port, user, password, timeout, cm, params)
	})
	cb := GetCircuitBreaker()
	origThreshold := cb.threshold
	cb.SetThreshold(threshold)
	cb.Reset(hostKey)
	return func() {
		cb.Reset(hostKey)
		cb.SetThreshold(origThreshold)
	}
}

var (
	// RDP-style: reachable host, credentials rejected (ErrKindAuth maps here).
	breakerAuthFail = BruteFunc(func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: errors.New("credentials rejected")}
	})
	breakerConnFail = BruteFunc(func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: errors.New("connection refused")}
	})
	breakerAuthOK = BruteFunc(func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
)

// Issue #366: RDP auth failures return ConnectionSuccess=true. They must not
// reset the breaker counter, so interleaved auth failures cannot indefinitely
// defer the skip threshold.
func TestRunBruteBreakerTripsThroughAuthFailures(t *testing.T) {
	const hostKey = "127.0.0.1:65010"
	cleanup := breakerTestService(t, "breaker-auth-fail-test", hostKey, 3,
		breakerAuthFail, breakerConnFail, breakerAuthFail, breakerConnFail, breakerConnFail)
	defer cleanup()
	defer func(orig bool) { modules.TUIMode = orig }(modules.TUIMode)
	modules.TUIMode = true

	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	host := modules.Host{Host: "127.0.0.1", Port: 65010, Service: "breaker-auth-fail-test"}
	attempt := func() BruteResult {
		return RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)
	}

	// auth-fail, conn-fail(1), auth-fail, conn-fail(2)
	attempt()
	attempt()
	attempt()
	attempt()
	if GetCircuitBreaker().IsTripped(hostKey) {
		t.Fatal("breaker tripped too early after 2 connection failures with threshold 3")
	}
	// conn-fail(3) → trip despite the interleaved auth failures.
	attempt()
	if !GetCircuitBreaker().IsTripped(hostKey) {
		t.Fatal("breaker must trip on the 3rd connection failure despite interleaved auth failures")
	}

	// Subsequent attempts are skipped without invoking the module.
	if got := attempt(); got.Status != StatusSkippedService {
		t.Fatalf("status after trip = %q, want %q", got.Status, StatusSkippedService)
	}
}

func TestRunBruteBreakerResetsOnAuthSuccess(t *testing.T) {
	const hostKey = "127.0.0.1:65011"
	cleanup := breakerTestService(t, "breaker-auth-success-test", hostKey, 3,
		breakerConnFail, breakerConnFail, breakerAuthOK, breakerConnFail, breakerConnFail)
	defer cleanup()
	defer func(orig bool) { modules.TUIMode = orig }(modules.TUIMode)
	modules.TUIMode = true

	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	host := modules.Host{Host: "127.0.0.1", Port: 65011, Service: "breaker-auth-success-test"}
	attempt := func() BruteResult {
		return RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)
	}

	// Two connection failures → counter 2 (threshold 3).
	attempt()
	attempt()
	// Auth success must clear the counter.
	if got := attempt(); !got.AuthSuccess {
		t.Fatalf("expected auth success, got status %q", got.Status)
	}
	// Two more connection failures must NOT trip post-reset.
	attempt()
	attempt()
	if GetCircuitBreaker().IsTripped(hostKey) {
		t.Fatal("breaker must not trip after auth success reset + 2 connection failures")
	}
}

func TestRunBruteSetsAttemptStatus(t *testing.T) {
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	tests := []struct {
		name       string
		service    string
		result     *BruteResult
		wantStatus AttemptStatus
	}{
		{
			name:       "auth success",
			service:    "status-success-test",
			result:     &BruteResult{AuthSuccess: true, ConnectionSuccess: true},
			wantStatus: StatusAuthSuccess,
		},
		{
			name:       "auth failure",
			service:    "status-auth-failure-test",
			result:     &BruteResult{AuthSuccess: false, ConnectionSuccess: true},
			wantStatus: StatusAuthFailure,
		},
		{
			name:       "connection failure",
			service:    "status-connection-failure-test",
			result:     &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: errors.New("dial failed")},
			wantStatus: StatusConnectionFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Register(tt.service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
				return tt.result
			})
			host := modules.Host{Host: "127.0.0.1", Port: 65001, Service: tt.service}
			GetCircuitBreaker().Reset("127.0.0.1:65001")

			got := RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)

			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
		})
	}
}

func TestRunBruteSetsUnsupportedStatus(t *testing.T) {
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	host := modules.Host{Host: "127.0.0.1", Port: 65002, Service: "status-unsupported-test"}
	GetCircuitBreaker().Reset("127.0.0.1:65002")

	got := RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)

	if got.Status != StatusUnsupportedService {
		t.Fatalf("status = %q, want %q", got.Status, StatusUnsupportedService)
	}
}

func TestRunBruteRecoversPanickingModule(t *testing.T) {
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	service := "panic-module-test"
	Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		panic("boom")
	})
	host := modules.Host{Host: "127.0.0.1", Port: 65003, Service: service}
	GetCircuitBreaker().Reset("127.0.0.1:65003")

	got := RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)

	if got.Status != StatusModulePanic {
		t.Fatalf("status = %q, want %q", got.Status, StatusModulePanic)
	}
	if got.Error == nil {
		t.Fatal("expected panic error to be recorded")
	}
}

func TestRunBruteTimesOutHungModule(t *testing.T) {
	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	service := "timeout-module-test"
	Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
		time.Sleep(500 * time.Millisecond)
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
	host := modules.Host{Host: "127.0.0.1", Port: 65004, Service: service}
	GetCircuitBreaker().Reset("127.0.0.1:65004")

	start := time.Now()
	got := RunBrute(host, "user", "pass", 25*time.Millisecond, 1, t.TempDir(), "", "", "", cm, nil)
	elapsed := time.Since(start)

	if got.Status != StatusModuleTimeout {
		t.Fatalf("status = %q, want %q", got.Status, StatusModuleTimeout)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("RunBrute took %v, want timeout containment under 250ms", elapsed)
	}
}

func TestRunBruteJSONOutputIncludesStatusCode(t *testing.T) {
	origFormat := modules.OutputFormatMode
	origSilent := modules.Silent
	origTUI := modules.TUIMode
	origNoColor := modules.NoColorMode
	t.Cleanup(func() {
		modules.OutputFormatMode = origFormat
		modules.Silent = origSilent
		modules.TUIMode = origTUI
		modules.NoColorMode = origNoColor
	})

	modules.OutputFormatMode = "json"
	modules.Silent = false
	modules.TUIMode = false
	modules.NoColorMode = true

	cm, err := modules.NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	service := "json-status-code-test"
	Register(service, func(string, int, string, string, time.Duration, *modules.ConnectionManager, ModuleParams) *BruteResult {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: errors.New("dial failed")}
	})
	host := modules.Host{Host: "127.0.0.1", Port: 65006, Service: service}
	GetCircuitBreaker().Reset("127.0.0.1:65006")

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	got := RunBrute(host, "user", "pass", time.Second, 1, t.TempDir(), "", "", "", cm, nil)
	_ = w.Close()
	os.Stdout = old

	if got.Status != StatusConnectionFailure {
		t.Fatalf("RunBrute status = %q, want %q", got.Status, StatusConnectionFailure)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	var attempt modules.AttemptResult
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &attempt); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if attempt.StatusCode != string(StatusConnectionFailure) {
		t.Fatalf("status_code = %q, want %q", attempt.StatusCode, StatusConnectionFailure)
	}
}
