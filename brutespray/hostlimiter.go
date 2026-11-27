package brutespray

import "sync"

// hostSlotLimiter caps concurrent in-flight hosts (issue #378).
//
// It replaces the previous buffered-channel semaphore. The channel design
// broke on every online SetHostParallelism (TUI settings arrows): the resize
// drained the old channel into a fresh one, but in-flight ProcessHost calls
// had captured the old channel for BOTH acquire and release. The verified
// defect (red in TestHostsReturnAcrossParallelismResize): the final
// old-generation release blocked forever receiving from an empty, abandoned
// channel, so that ProcessHost never returned and its host slot was never
// freed. A count-based limiter has no ownership to transfer: resize only
// changes the limit and broadcasts, so acquires and releases are always
// against the same object.
//
// The wake-channel broadcast pattern matches brute.CircuitBreaker.AdmitDial
// and hostTurnScheduler.waitTurn.
type hostSlotLimiter struct {
	mu    sync.Mutex
	inUse int
	limit int
	wake  chan struct{} // closed and replaced whenever a slot frees or limit rises
}

func newHostSlotLimiter(limit int) *hostSlotLimiter {
	if limit < 1 {
		limit = 1
	}
	return &hostSlotLimiter{limit: limit, wake: make(chan struct{})}
}

// broadcastLocked wakes every waiter; callers must hold mu.
func (l *hostSlotLimiter) broadcastLocked() {
	close(l.wake)
	l.wake = make(chan struct{})
}

// acquire blocks until a slot is free, then takes it and returns true. It
// returns false only if stop is closed first, in which case no slot is held.
//
// The wake channel is captured while holding mu: if a release or a limit
// raise lands between the check and the select, the captured channel is
// already closed and the select returns immediately, so no wake can be lost.
func (l *hostSlotLimiter) acquire(stop <-chan struct{}) bool {
	l.mu.Lock()
	for {
		if l.inUse < l.limit {
			l.inUse++
			l.mu.Unlock()
			return true
		}
		wake := l.wake
		l.mu.Unlock()
		select {
		case <-wake:
		case <-stop:
			return false
		}
		l.mu.Lock()
	}
}

// release gives back one held slot and wakes a waiter. Releasing into a
// limiter whose limit was lowered since acquire is fine: the count simply
// drains toward the new limit.
func (l *hostSlotLimiter) release() {
	l.mu.Lock()
	if l.inUse > 0 {
		l.inUse--
	}
	l.broadcastLocked()
	l.mu.Unlock()
}

// setLimit raises or lowers the cap without stranding anyone: raising
// broadcasts so parked hosts admit immediately; lowering takes effect as
// holders release.
func (l *hostSlotLimiter) setLimit(n int) {
	if n < 1 {
		n = 1
	}
	l.mu.Lock()
	l.limit = n
	l.broadcastLocked()
	l.mu.Unlock()
}

// running reports the number of held slots (test observability).
func (l *hostSlotLimiter) running() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inUse
}
