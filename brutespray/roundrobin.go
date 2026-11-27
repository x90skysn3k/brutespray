package brutespray

import (
	"sync"
)

// hostTurnScheduler interleaves credential queueing across hosts in
// round-robin order (issue #150). Without it every host goroutine enqueues
// its whole credential list as fast as its queue buffer allows, so one host
// gets hammered to completion (or skipped by the breaker) while later hosts
// in the same run see nothing:
//
//	Host#1 - Combo#1 ... Host#1 - Combo#N, Host#2 - Combo#1 ...
//
// With it the queueing alternates:
//
//	Host#1 - Combo#1, Host#2 - Combo#1, ..., Host#1 - Combo#2, ...
//
// A host becomes a rotation participant when it first reaches the enqueue
// gate (hosts blocked on the host-parallelism semaphore are skipped until
// they are actually ready, so the rotation can never deadlock on a host that
// has not started). Hosts that finished queueing leave(); departed hosts are
// skipped. When a host is the only ready participant it proceeds at full
// speed.
type hostTurnScheduler struct {
	mu      sync.Mutex
	planned []string        // host keys in registration order
	ready   map[string]bool // reached the enqueue gate at least once
	left    map[string]bool // finished queueing (or aborted)
	stalled map[string]bool // queue buffer full; temporarily not participating
	cursor  string          // host key that last held the turn
	wake    chan struct{}   // close-to-broadcast generation channel
}

func newHostTurnScheduler() *hostTurnScheduler {
	return &hostTurnScheduler{
		ready:   make(map[string]bool),
		left:    make(map[string]bool),
		stalled: make(map[string]bool),
		wake:    make(chan struct{}),
	}
}

// plan records a host in the rotation order before the run starts, so the
// interleave follows the operator's target order. Unknown hosts are
// appended on first use, so this is best-effort, not required.
func (s *hostTurnScheduler) plan(hostKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.planned {
		if k == hostKey {
			return
		}
	}
	s.planned = append(s.planned, hostKey)
}

func (s *hostTurnScheduler) broadcastLocked() {
	close(s.wake)
	s.wake = make(chan struct{})
}

// pickLocked returns the host that should hold the turn: the first ready,
// not-left host after the cursor in planned order, wrapping once. Returns
// "" when no other participant is ready (the waiting host then self-paces).
// Callers hold s.mu.
func (s *hostTurnScheduler) pickLocked() string {
	n := len(s.planned)
	if n == 0 {
		return ""
	}
	start := 0
	if s.cursor != "" {
		for i, k := range s.planned {
			if k == s.cursor {
				start = i + 1
				break
			}
		}
	}
	for i := 0; i < n; i++ {
		k := s.planned[(start+i)%n]
		if s.ready[k] && !s.left[k] && !s.stalled[k] {
			return k
		}
	}
	return ""
}

// stall marks hostKey as temporarily unable to accept a credential (its
// queue buffer is full while the driver blocks on the send). pickLocked
// skips stalled hosts so the rotation never deadlocks behind a slow or
// paused host.
func (s *hostTurnScheduler) stall(hostKey string) {
	s.mu.Lock()
	s.stalled[hostKey] = true
	s.broadcastLocked()
	s.mu.Unlock()
}

// unstall returns hostKey to the rotation after a blocked send completed.
func (s *hostTurnScheduler) unstall(hostKey string) {
	s.mu.Lock()
	delete(s.stalled, hostKey)
	s.broadcastLocked()
	s.mu.Unlock()
}

// waitTurn blocks until hostKey holds the turn, then returns true. Returns
// false when hostStop or globalStop closes first (caller abandons queueing).
// A host with no other ready participant self-paces: it does not wait on
// hosts that have not reached the gate or already left.
func (s *hostTurnScheduler) waitTurn(hostKey string, hostStop, globalStop <-chan struct{}) bool {
	s.mu.Lock()
	var known bool
	for _, k := range s.planned {
		if k == hostKey {
			known = true
			break
		}
	}
	if !known {
		s.planned = append(s.planned, hostKey)
	}
	s.ready[hostKey] = true
	s.broadcastLocked()
	for {
		pick := s.pickLocked()
		if pick == "" || pick == hostKey {
			s.mu.Unlock()
			return true
		}
		wake := s.wake
		s.mu.Unlock()
		select {
		case <-wake:
			s.mu.Lock()
			continue
		case <-hostStop:
			return false
		case <-globalStop:
			return false
		}
	}
}

// advance hands the turn to the next ready host after hostKey. Called after
// one successful credential enqueue so each host contributes exactly one
// credential per rotation.
func (s *hostTurnScheduler) advance(hostKey string) {
	s.mu.Lock()
	s.cursor = hostKey
	s.broadcastLocked()
	s.mu.Unlock()
}

// leave removes hostKey from the rotation once it has finished queueing.
func (s *hostTurnScheduler) leave(hostKey string) {
	s.mu.Lock()
	if !s.left[hostKey] {
		s.left[hostKey] = true
		s.broadcastLocked()
	}
	s.mu.Unlock()
}
