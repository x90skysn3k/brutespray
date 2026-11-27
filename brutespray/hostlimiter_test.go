package brutespray

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// Issue #378 (reporter clarification 2026-11-27): "when the hosts with conn
// failure skip and finished. new hosts didnt came to que". The host
// concurrency semaphore was a buffered channel that SetHostParallelism
// REPLACED on resize, while every in-flight ProcessHost had captured the old
// channel for both its acquire (send) and release (receive). A resize drains
// the old channel, so old-generation releases start stealing queued hosts'
// acquire tokens one-for-one — and the LAST old-generation host blocks
// forever in `<-oldSem` with no sender left. Its ProcessHost never returns,
// hostWg.Wait never completes, and the run never finishes.
//
// The completion EVENT is not proof: HostCompletedMsg is sent before the
// deferred release runs. These tests assert every ProcessHost call RETURNS.
// Verified pre-fix behavior (red): after a resize, the last old-generation
// release blocks forever, so ProcessHost never returns, the slot leaks, and
// the run never completes. Whether the reporter's run hit exactly this
// path (versus start-stranding at the -T cap) is unconfirmed — their input
// is still unknown; these tests pin the defect itself.

func resizeFixture(t *testing.T, service string, portBase int, hostCount int, connOK bool, latency time.Duration) (func(modules.Host, *WorkerPool, *captureDispatchEventSink) error, *brute.CircuitBreaker, func()) {
	t.Helper()
	var calls atomic.Int64
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		calls.Add(1)
		time.Sleep(latency)
		if connOK {
			return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: net.ErrClosed}
	})

	cb := brute.GetCircuitBreaker()
	origThreshold, origDisabled := cb.GetThreshold(), cb.IsDisabled()
	ports := make([]int, hostCount)
	for i := range ports {
		ports[i] = portBase + i
		cb.Reset(fmt.Sprintf("127.0.0.1:%d", ports[i]))
	}
	cleanup := func() {
		for _, p := range ports {
			cb.Reset(fmt.Sprintf("127.0.0.1:%d", p))
		}
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}

	return func(h modules.Host, wp *WorkerPool, sink *captureDispatchEventSink) error {
		_ = sink
		pwFile := writeWordlist(t, "p1", "p2")
		cm, err := modules.NewConnectionManager("", 200*time.Millisecond)
		if err != nil {
			return err
		}
		wp.ProcessHost(h, h.Service, "", "u", pwFile, version, 200*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)
		return nil
	}, cb, cleanup
}

// TestHostsReturnAcrossParallelismResize is the deterministic red for the
// semaphore swap: -T=1, three hosts (A holds, B/C queued), then an online
// resize like the TUI settings arrows perform. Pre-fix, the resize drains
// A's token and the old channel's tokens get stolen hand-off by hand-off,
// so the last old-generation host's release blocks forever and its
// ProcessHost never returns.
func TestHostsReturnAcrossParallelismResize(t *testing.T) {
	runResizeReturnTest(t, 1, 2, 3, 45100, true)
}

func TestHostsReturnAcrossParallelismShrink(t *testing.T) {
	runResizeReturnTest(t, 2, 1, 4, 45120, true)
}

// Control: identical flow WITHOUT a resize must already work; it isolates
// the defect to the resize handoff rather than the semaphore steady state.
func TestHostsReturnWithoutResize(t *testing.T) {
	runResizeReturnTest(t, 1, 0, 3, 45140, true) // newPar 0 = no resize
}

// Dead-host variant matching the reporter's scenario: conn-failure hosts
// skipped by the breaker must release their slots for queued hosts,
// including across an online parallelism change.
func TestDeadHostsReturnAcrossResize(t *testing.T) {
	runResizeReturnTest(t, 1, 2, 3, 45160, false)
}

func runResizeReturnTest(t *testing.T, initialPar, newPar, hostCount, portBase int, connOK bool) {
	t.Helper()
	service := fmt.Sprintf("resizereturn%d", portBase)
	proc, cb, cleanup := resizeFixture(t, service, portBase, hostCount, connOK, 30*time.Millisecond)
	defer cleanup()
	if !connOK {
		cb.SetThreshold(2)
		cb.SetDisabled(false)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, initialPar, hostCount)
	wp.noStats = true

	hosts := make([]modules.Host, hostCount)
	for i := range hosts {
		hosts[i] = modules.Host{Service: service, Host: "127.0.0.1", Port: portBase + i}
	}

	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(host modules.Host) {
			defer wg.Done()
			if err := proc(host, wp, sink); err != nil {
				t.Errorf("ProcessHost(%d): %v", host.Port, err)
			}
		}(h)
	}

	if newPar > 0 {
		// Resize while the first batch is in flight and the rest are
		// queued on the slot semaphore (mirrors TUI settings arrows).
		time.Sleep(150 * time.Millisecond)
		wp.SetHostParallelism(newPar)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Every ProcessHost returned.
	case <-time.After(10 * time.Second):
		started, completed := sink.lifecycle()
		t.Fatalf("ProcessHost goroutines never returned after resize %d->%d (started=%d completed=%d of %d): host-slot release stranded behind a replaced semaphore", initialPar, newPar, started, completed, hostCount)
	}

	started, completed := sink.lifecycle()
	if started != hostCount || completed != hostCount {
		t.Fatalf("lifecycle counts started=%d completed=%d, want %d/%d", started, completed, hostCount, hostCount)
	}
}

// Direct limiter contract: a parked acquire is admitted the instant the
// limit is raised, and stop-cancellation never leaks a slot.
func TestHostSlotLimiterGrowAdmitsParkedHost(t *testing.T) {
	l := newHostSlotLimiter(1)
	if !l.acquire(nil) {
		t.Fatal("first acquire failed")
	}
	if l.running() != 1 {
		t.Fatalf("running=%d want 1", l.running())
	}

	admitted := make(chan bool, 1)
	go func() { admitted <- l.acquire(nil) }()
	select {
	case <-admitted:
		t.Fatal("second acquire succeeded at limit=1")
	case <-time.After(100 * time.Millisecond):
	}

	l.setLimit(2) // grow while parked
	select {
	case ok := <-admitted:
		if !ok {
			t.Fatal("parked acquire returned false after grow")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked acquire never admitted after setLimit grow")
	}

	l.release()
	l.release()
	if l.running() != 0 {
		t.Fatalf("running=%d after releases want 0", l.running())
	}
}

func TestHostSlotLimiterShrinkDrainsAsHostsFinish(t *testing.T) {
	l := newHostSlotLimiter(3)
	for range 3 {
		if !l.acquire(nil) {
			t.Fatal("acquire failed below limit")
		}
	}
	l.setLimit(1) // shrink; holders keep running, new admits blocked
	admitted := make(chan bool, 1)
	go func() { admitted <- l.acquire(nil) }()
	select {
	case <-admitted:
		t.Fatal("acquire admitted above shrunken limit")
	case <-time.After(100 * time.Millisecond):
	}
	for range 3 {
		l.release()
	}
	select {
	case ok := <-admitted:
		if !ok {
			t.Fatal("acquire returned false after drain")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire never admitted after all holders released")
	}
	l.release()
}

// A blocked acquire canceled via stop must return false WITHOUT taking a
// slot (the #378 dispatch path passes wp.globalStopChan here).
func TestHostSlotLimiterStopCancelsAcquire(t *testing.T) {
	l := newHostSlotLimiter(1)
	if !l.acquire(nil) {
		t.Fatal("first acquire failed")
	}
	stop := make(chan struct{})
	result := make(chan bool, 1)
	go func() { result <- l.acquire(stop) }()
	time.Sleep(50 * time.Millisecond) // let it park at the limit
	close(stop)
	select {
	case ok := <-result:
		if ok {
			t.Fatal("acquire returned true after stop closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked acquire ignored stop channel")
	}
	if got := l.running(); got != 1 {
		t.Fatalf("running=%d after canceled acquire, want 1 — a canceled acquire must not take a slot", got)
	}
	l.release()
	if l.running() != 0 {
		t.Fatalf("running=%d after release, want 0", l.running())
	}
}
