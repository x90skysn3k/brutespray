package brutespray

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestHostPoolsShareBudgetSchedulerByIdentity(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scheduler := NewBudgetScheduler(LockoutPolicy{LockoutThreshold: 2, SafeMargin: 1, LockoutWindow: time.Minute}, start)
	first := NewHostWorkerPool(modules.Host{Service: "ssh", Host: "10.0.0.1", Port: 22}, 1, nil, false, 0)
	second := NewHostWorkerPool(modules.Host{Service: "ssh", Host: "10.0.0.2", Port: 22}, 1, nil, false, 0)
	first.budgetScheduler = scheduler
	second.budgetScheduler = scheduler

	cred1 := Credential{Host: first.host, Service: "ssh", User: "root"}
	cred2 := Credential{Host: second.host, Service: "ssh", User: "root"}
	if delay := first.reserveBudgetAt(cred1, "", start); delay != 0 {
		t.Fatalf("first reserve delay = %v", delay)
	}
	if delay := second.reserveBudgetAt(cred2, "", start.Add(time.Second)); delay <= 0 {
		t.Fatalf("second host same identity delay = %v, want positive", delay)
	}
}
