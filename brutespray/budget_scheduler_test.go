package brutespray

import (
	"testing"
	"time"
)

func TestBudgetSchedulerAllowsBudgetWithinWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scheduler := NewBudgetScheduler(LockoutPolicy{LockoutThreshold: 5, SafeMargin: 1, LockoutWindow: 15 * time.Minute}, start)
	id := NewAttemptIdentity("ssh", "", "root")
	for i := 0; i < 4; i++ {
		if delay := scheduler.DelayBefore(id, start.Add(time.Duration(i)*time.Minute)); delay != 0 {
			t.Fatalf("attempt %d delay = %v, want 0", i+1, delay)
		}
		scheduler.Record(id, start.Add(time.Duration(i)*time.Minute))
	}
	if delay := scheduler.DelayBefore(id, start.Add(4*time.Minute)); delay <= 0 {
		t.Fatalf("5th attempt delay = %v, want positive", delay)
	}
}

func TestBudgetSchedulerReserveIsAtomic(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scheduler := NewBudgetScheduler(LockoutPolicy{LockoutThreshold: 3, SafeMargin: 1, LockoutWindow: 10 * time.Minute}, start)
	id := NewAttemptIdentity("ssh", "", "root")
	if delay := scheduler.Reserve(id, start); delay != 0 {
		t.Fatalf("first reserve delay = %v", delay)
	}
	if delay := scheduler.Reserve(id, start.Add(time.Second)); delay != 0 {
		t.Fatalf("second reserve delay = %v", delay)
	}
	if delay := scheduler.Reserve(id, start.Add(2*time.Second)); delay <= 0 {
		t.Fatalf("third reserve delay = %v, want positive", delay)
	}
}

func TestBudgetSchedulerWindowExpires(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scheduler := NewBudgetScheduler(LockoutPolicy{LockoutThreshold: 3, SafeMargin: 1, LockoutWindow: 10 * time.Minute}, start)
	id := NewAttemptIdentity("ssh", "", "root")
	scheduler.Record(id, start)
	scheduler.Record(id, start.Add(time.Minute))
	if delay := scheduler.DelayBefore(id, start.Add(11*time.Minute)); delay != 0 {
		t.Fatalf("delay after window = %v, want 0", delay)
	}
}
