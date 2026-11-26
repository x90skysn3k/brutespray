package brutespray

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// Issue #150: -schedule round-robin must interleave credential queueing
// across hosts (Host#1 Combo#1, Host#2 Combo#1, Host#1 Combo#2, ...)
// instead of one host getting its whole list enqueued while other hosts
// idle. The scheduler unit tests below pin the strict turn order; the
// ProcessHost integration test pins the seam: the mode wires through,
// every credential still runs exactly once per host, each host keeps a
// single lifecycle, and nothing deadlocks.

func TestHostTurnSchedulerAlternates(t *testing.T) {
	s := newHostTurnScheduler()
	s.plan("A:1/svc")
	s.plan("B:1/svc")

	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Pre-register both participants so neither can legally self-pace
	// while the other has not registered yet: with both ready, the pick
	// always exists and the rotation is strict from the first turn.
	s.ready["A:1/svc"] = true
	s.ready["B:1/svc"] = true

	// Both drivers enqueue `rounds` credentials each through the gate.
	const rounds = 8
	for _, key := range []string{"A:1/svc", "B:1/svc"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if !s.waitTurn(key, stop, nil) {
					return
				}
				mu.Lock()
				order = append(order, key)
				mu.Unlock()
				s.advance(key)
			}
			s.leave(key)
		}(key)
	}
	wg.Wait()
	close(stop)

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2*rounds {
		t.Fatalf("enqueued %d entries, want %d", len(order), 2*rounds)
	}
	// With both hosts ready the rotation must strictly alternate: no
	// host may hold the turn twice in a row.
	for i := 1; i < len(order); i++ {
		if order[i] == order[i-1] {
			t.Fatalf("rotation not interleaved at %d: %v", i, order)
		}
	}
}

func TestHostTurnSchedulerDepartedHostDoesNotBlockRotation(t *testing.T) {
	s := newHostTurnScheduler()
	s.plan("A:1/svc")
	s.plan("B:1/svc")

	// B reached the gate once, then left; A must proceed at full speed.
	s.ready["B:1/svc"] = true
	s.left["B:1/svc"] = true

	done := make(chan struct{})
	go func() {
		for i := 0; i < 3; i++ {
			if !s.waitTurn("A:1/svc", done, nil) {
				return
			}
			s.advance("A:1/svc")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation blocked on a departed host")
	}
}

// TestHostTurnSchedulerBlocksBehindOtherHost pins the actual turn gate:
// with both hosts ready and the cursor on B, the pick lands on A, so a B
// driver must BLOCK rather than self-pace, and is released when A takes
// its turn (advance(A) puts B up next).
func TestHostTurnSchedulerBlocksBehindOtherHost(t *testing.T) {
	s := newHostTurnScheduler()
	s.plan("A:1/svc")
	s.plan("B:1/svc")
	s.ready["A:1/svc"] = true
	s.ready["B:1/svc"] = true
	s.advance("B:1/svc") // cursor = B; pick resolves to A → B must wait

	blocked := make(chan bool, 1)
	go func() { blocked <- s.waitTurn("B:1/svc", nil, nil) }()
	select {
	case got := <-blocked:
		t.Fatalf("waitTurn(B) returned %v immediately; B must wait for A's turn", got)
	case <-time.After(100 * time.Millisecond):
		// still blocked — correct
	}

	// A takes its turn: cursor moves to A, so the pick becomes B.
	s.advance("A:1/svc")
	select {
	case got := <-blocked:
		if !got {
			t.Fatal("waitTurn(B) returned false without stop channels")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitTurn(B) not released after A advanced")
	}
}

// TestHostTurnSchedulerStalledHostSelfPaces: when the only other
// participant is stalled (its queue buffer is full), B self-paces instead
// of deadlocking behind it.
func TestHostTurnSchedulerStalledHostSelfPaces(t *testing.T) {
	s := newHostTurnScheduler()
	s.plan("A:1/svc")
	s.ready["A:1/svc"] = true
	s.advance("A:1/svc")
	s.stall("A:1/svc") // A's queue is full

	got := make(chan bool, 1)
	go func() { got <- s.waitTurn("B:1/svc", nil, nil) }()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("waitTurn(B) returned false without stop channels")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitTurn(B) blocked behind a stalled host")
	}
}

func TestHostTurnSchedulerStopUnblocks(t *testing.T) {
	s := newHostTurnScheduler()
	s.plan("A:1/svc")
	s.plan("B:1/svc")
	s.ready["A:1/svc"] = true
	s.ready["B:1/svc"] = true
	s.advance("B:1/svc") // cursor B: pick is A, so B holds no turn

	stop := make(chan struct{})
	got := make(chan bool, 1)
	go func() { got <- s.waitTurn("B:1/svc", stop, nil) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-got:
		t.Fatal("B was granted a turn despite A holding it")
	default:
	}
	close(stop)
	select {
	case ok := <-got:
		if ok {
			t.Fatal("waitTurn must return false after stop closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitTurn did not unblock on stop")
	}
}

// TestRoundRobinProcessHostIntegration is the ProcessHost-seam contract
// for issue #150: with -schedule round-robin active, two hosts run to
// completion with every credential attempted exactly once, exactly one
// lifecycle event pair per host, and no deadlock. (The strict
// cross-host turn order is pinned by the scheduler unit tests above.)
func TestRoundRobinProcessHostIntegration(t *testing.T) {
	const service = "rrsvc"
	const creds = 12

	var counts sync.Map // hostKey -> *atomic.Int64
	brute.Register(service, func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		key := net.JoinHostPort(host, strconv.Itoa(port))
		v, _ := counts.LoadOrStore(key, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
		return &brute.BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})

	cb := brute.GetCircuitBreaker()
	origThreshold, origDisabled := cb.GetThreshold(), cb.IsDisabled()
	ports := []int{45011, 45012}
	for _, p := range ports {
		cb.Reset(fmt.Sprintf("127.0.0.1:%d", p))
	}
	defer func() {
		for _, p := range ports {
			cb.Reset(fmt.Sprintf("127.0.0.1:%d", p))
		}
		cb.SetThreshold(origThreshold)
		cb.SetDisabled(origDisabled)
	}()

	pwFile := writeWordlist(t, credentialLines(creds)...)
	cm, err := modules.NewConnectionManager("", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 5, 2)
	wp.noStats = true
	wp.scheduleMode = "round-robin"
	wp.roundRobin = newHostTurnScheduler()

	hostA := modules.Host{Service: service, Host: "127.0.0.1", Port: ports[0]}
	hostB := modules.Host{Service: service, Host: "127.0.0.1", Port: ports[1]}
	wp.PlanTargets([]modules.Host{hostA, hostB})

	var wg sync.WaitGroup
	for _, h := range []modules.Host{hostA, hostB} {
		wg.Add(1)
		go func(host modules.Host) {
			defer wg.Done()
			wp.ProcessHost(host, service, "", "u", pwFile, version, 100*time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)
		}(h)
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("round-robin run deadlocked")
	}

	for _, p := range ports {
		key := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
		v, ok := counts.Load(key)
		if !ok {
			t.Fatalf("host %s received no attempts", key)
		}
		if got := v.(*atomic.Int64).Load(); got != creds {
			t.Fatalf("host %s attempts = %d, want %d (credentials lost or duplicated)", key, got, creds)
		}
	}
	started, completed := sink.lifecycle()
	if started != 2 || completed != 2 {
		t.Fatalf("lifecycle events = started %d, completed %d; want 2/2", started, completed)
	}
}

// credentialLines builds n distinct fake passwords.
func credentialLines(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("pw%03d", i)
	}
	return out
}
