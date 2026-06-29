package brutespray

import (
	"math/rand"
	"sync"
	"time"
)

// BudgetScheduler tracks lockout-window attempt budgets per account identity.
type BudgetScheduler struct {
	policy   LockoutPolicy
	mu       sync.Mutex
	attempts map[string][]time.Time
	jitter   func(time.Duration) time.Duration
}

// NewBudgetScheduler creates a scheduler for policy. The now parameter is kept for call-site clarity.
func NewBudgetScheduler(policy LockoutPolicy, now time.Time) *BudgetScheduler {
	_ = now
	return &BudgetScheduler{
		policy:   policy,
		attempts: make(map[string][]time.Time),
		jitter: func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(rand.Int63n(int64(max) + 1))
		},
	}
}

// DelayBefore returns how long to wait before the next attempt for id at now.
func (s *BudgetScheduler) DelayBefore(id AttemptIdentity, now time.Time) time.Duration {
	if s == nil || s.policy.EffectiveBudget() == 0 || s.policy.LockoutWindow <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.Key()
	recent := pruneBefore(s.attempts[key], now.Add(-s.policy.LockoutWindow))
	s.attempts[key] = recent
	return s.delayForRecent(recent, now)
}

// Reserve atomically checks and consumes one attempt budget slot.
func (s *BudgetScheduler) Reserve(id AttemptIdentity, now time.Time) time.Duration {
	if s == nil || s.policy.EffectiveBudget() == 0 || s.policy.LockoutWindow <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.Key()
	recent := pruneBefore(s.attempts[key], now.Add(-s.policy.LockoutWindow))
	if delay := s.delayForRecent(recent, now); delay > 0 {
		s.attempts[key] = recent
		return delay
	}
	s.attempts[key] = append(recent, now)
	return 0
}

// Record stores an observed attempt timestamp for id.
func (s *BudgetScheduler) Record(id AttemptIdentity, at time.Time) {
	if s == nil || s.policy.EffectiveBudget() == 0 || s.policy.LockoutWindow <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.Key()
	recent := pruneBefore(s.attempts[key], at.Add(-s.policy.LockoutWindow))
	recent = append(recent, at)
	s.attempts[key] = recent
}

func (s *BudgetScheduler) delayForRecent(recent []time.Time, now time.Time) time.Duration {
	if len(recent) < s.policy.EffectiveBudget() {
		return 0
	}
	readyAt := recent[0].Add(s.policy.LockoutWindow)
	if !readyAt.After(now) {
		return 0
	}
	return s.withJitter(readyAt.Sub(now))
}

func (s *BudgetScheduler) withJitter(delay time.Duration) time.Duration {
	if delay <= 0 || s.policy.JitterPercent <= 0 || s.jitter == nil {
		return delay
	}
	max := time.Duration(int64(delay) * int64(s.policy.JitterPercent) / 100)
	return delay + s.jitter(max)
}

func pruneBefore(attempts []time.Time, cutoff time.Time) []time.Time {
	keep := 0
	for keep < len(attempts) && !attempts[keep].After(cutoff) {
		keep++
	}
	return attempts[keep:]
}
