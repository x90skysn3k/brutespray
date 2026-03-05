package brute

import (
	"context"
	"testing"
	"time"
)

func TestRunWithTimeoutSuccess(t *testing.T) {
	result := RunWithTimeout(5*time.Second, func(ctx context.Context) *BruteResult {
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})

	if !result.AuthSuccess || !result.ConnectionSuccess {
		t.Fatal("expected auth and connection success")
	}
}

func TestRunWithTimeoutAuthFailure(t *testing.T) {
	result := RunWithTimeout(5*time.Second, func(ctx context.Context) *BruteResult {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestRunWithTimeoutExpired(t *testing.T) {
	result := RunWithTimeout(50*time.Millisecond, func(ctx context.Context) *BruteResult {
		// Simulate a slow operation
		select {
		case <-ctx.Done():
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
		case <-time.After(5 * time.Second):
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		}
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure on timeout")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure on timeout")
	}
	if result.Error == nil {
		t.Fatal("expected error on timeout")
	}
}

func TestRunWithTimeoutContextCancellation(t *testing.T) {
	// Verify the context is cancelled when timeout fires
	result := RunWithTimeout(50*time.Millisecond, func(ctx context.Context) *BruteResult {
		<-ctx.Done()
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
	})

	if result.Error == nil {
		t.Fatal("expected context cancellation error")
	}
}
