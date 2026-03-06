package brute

import (
	"testing"
	"time"
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
