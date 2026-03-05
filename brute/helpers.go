package brute

import (
	"context"
	"time"
)

// RunWithTimeout executes fn with the given timeout. If the function does not
// complete within the timeout, a result with ConnectionSuccess=false is returned.
// The context passed to fn will be cancelled on timeout, allowing cooperative
// cancellation inside the function.
func RunWithTimeout(timeout time.Duration, fn func(ctx context.Context) *BruteResult) *BruteResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan *BruteResult, 1)
	go func() {
		done <- fn(ctx)
	}()

	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		// Try to drain a result that may have arrived concurrently
		select {
		case result := <-done:
			return result
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
		}
	}
}
