package brutespray

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

type retirementSink struct {
	captureDispatchEventSink
	progress atomic.Int64
}

func (s *retirementSink) Send(msg interface{}) {
	s.captureDispatchEventSink.Send(msg)
	if _, ok := msg.(tui.ProgressEvent); ok {
		s.progress.Add(1)
	}
}

// Observe the actual pool seam, including admission of the waiting target,
// persisted attempts, and completion after a huge unconsumed Cartesian suffix.
func TestProcessHostRetiresHugeTrippedTargetBeforeNextHost(t *testing.T) {
	const service = "retirement-trip"
	const threshold = 10
	first := modules.Host{Host: "127.0.0.1", Port: 45901, Service: service}
	next := modules.Host{Host: "127.0.0.1", Port: 45902, Service: service}
	cb := brute.GetCircuitBreaker()
	oldThreshold, oldDisabled := cb.GetThreshold(), cb.IsDisabled()
	cb.SetThreshold(threshold)
	cb.SetDisabled(false)
	for _, h := range []modules.Host{first, next} {
		cb.Reset(net.JoinHostPort(h.Host, fmt.Sprint(h.Port)))
	}
	defer func() {
		for _, h := range []modules.Host{first, next} {
			cb.Reset(net.JoinHostPort(h.Host, fmt.Sprint(h.Port)))
		}
		cb.SetThreshold(oldThreshold)
		cb.SetDisabled(oldDisabled)
	}()

	var calls atomic.Int64
	var active atomic.Int64
	var overlap atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	brute.Register(service, func(_ string, port int, _, _ string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		if port == first.Port {
			active.Add(1)
			defer active.Add(-1)
			once.Do(func() { close(entered) })
			<-release
			calls.Add(1)
			return &brute.BruteResult{Error: os.ErrDeadlineExceeded}
		}
		if active.Load() != 0 {
			overlap.Store(true)
		}
		return &brute.BruteResult{ConnectionSuccess: true}
	})
	var lines strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&lines, "value-%d\n", i)
	}
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &retirementSink{}
	wp := NewWorkerPool(30, sink, 1, 2)
	wp.noStats = true
	wp.checkpoint = modules.NewCheckpoint("")
	logPath := filepath.Join(t.TempDir(), "session.jsonl")
	wp.sessionLog, err = modules.NewSessionLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer wp.sessionLog.Close()
	done := make(chan struct{}, 2)
	output := t.TempDir()
	go func() {
		wp.ProcessHost(first, service, "", wordlist, wordlist, version, 2*time.Second, 1, output, cm, "", nil, false)
		done <- struct{}{}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first target never attempted a credential")
	}
	go func() {
		wp.ProcessHost(next, service, "", "u", "p", version, 2*time.Second, 1, output, cm, "", nil, false)
		done <- struct{}{}
	}()
	close(release)
	for range 2 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			wp.Stop()
			t.Fatal("tripped target retained its host slot while consuming the huge suffix")
		}
	}
	wp.Stop()
	if overlap.Load() {
		t.Fatal("next host admitted before previous in-flight attempts joined")
	}
	if got := calls.Load(); got != threshold {
		t.Fatalf("actual attempts = %d, want %d", got, threshold)
	}
	if got := wp.checkpoint.GetAttemptedCount(first.Host, first.Port, service); got != threshold {
		t.Fatalf("checkpoint attempts = %d, want %d actual attempts", got, threshold)
	}
	if !wp.checkpoint.IsHostCompleted(first.Host, first.Port, service) {
		t.Fatal("tripped target not terminal in checkpoint")
	}
	if got := sink.progress.Load(); got != 0 {
		t.Fatalf("unconsumed suffix emitted %d phantom progress events", got)
	}
	if started, completed := sink.lifecycle(); started != 2 || completed != 2 {
		t.Fatalf("lifecycle = %d/%d, want exactly 2/2", started, completed)
	}
	attempts := sink.attemptResults()
	if len(attempts) != threshold+1 {
		t.Fatalf("attempt events = %d, want %d", len(attempts), threshold+1)
	}
	for _, a := range attempts {
		if a.Retrying || a.Status == string(brute.StatusSkippedService) {
			t.Fatalf("phantom or retry attempt: %#v", a)
		}
	}
	entries, err := modules.LoadSessionLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	loggedAttempts, loggedCompleted := 0, 0
	for _, entry := range entries {
		if entry.Port != first.Port {
			continue
		}
		switch entry.Type {
		case "attempt":
			loggedAttempts++
		case "host_completed":
			loggedCompleted++
			if entry.TotalAttempts != threshold {
				t.Fatalf("completed session attempts = %d, want %d", entry.TotalAttempts, threshold)
			}
		}
	}
	if loggedAttempts != threshold || loggedCompleted != 1 {
		t.Fatalf("session attempts/completions = %d/%d, want %d/1", loggedAttempts, loggedCompleted, threshold)
	}
}

func TestProcessHostStopOnSuccessCompletesAndAdmitsNextHost(t *testing.T) {
	const service = "retirement-success"
	brute.Register(service, func(_ string, _ int, _, password string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{ConnectionSuccess: true, AuthSuccess: password == "winner"}
	})
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &retirementSink{}
	wp := NewWorkerPool(1, sink, 1, 2)
	wp.noStats, wp.stopOnSuccess = true, true
	wp.checkpoint = modules.NewCheckpoint("")
	passwords := writeWordlist(t, "winner", "unused", "unused-again")
	for _, port := range []int{45903, 45904} {
		host := modules.Host{Host: "127.0.0.1", Port: port, Service: service}
		wp.ProcessHost(host, service, "", "u", passwords, version, 2*time.Second, 1, t.TempDir(), cm, "", nil, false)
		if got := wp.checkpoint.GetAttemptedCount(host.Host, port, service); got != 1 {
			t.Fatalf("host %d attempted %d credentials, want 1", port, got)
		}
		if !wp.checkpoint.IsHostCompleted(host.Host, port, service) {
			t.Fatalf("successful host %d missing terminal checkpoint", port)
		}
	}
	wp.Stop()
	if started, completed := sink.lifecycle(); started != 2 || completed != 2 {
		t.Fatalf("success lifecycle = %d/%d, want 2/2", started, completed)
	}
	if got := len(sink.attemptResults()); got != 2 {
		t.Fatalf("success attempt events = %d, want 2", got)
	}
}

func TestProcessHostSuccessJoinsInflightWorkersBeforeAdmission(t *testing.T) {
	const service = "retirement-success-join"
	first := modules.Host{Host: "127.0.0.1", Port: 45930, Service: service}
	next := modules.Host{Host: "127.0.0.1", Port: 45931, Service: service}
	holding, release := make(chan struct{}), make(chan struct{})
	winnerReturned, nextEntered := make(chan struct{}), make(chan struct{}, 1)
	brute.Register(service, func(_ string, port int, _, password string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		if port == next.Port {
			nextEntered <- struct{}{}
			return &brute.BruteResult{ConnectionSuccess: true}
		}
		if password == "hold" {
			close(holding)
			<-release
			return &brute.BruteResult{ConnectionSuccess: true}
		}
		<-holding
		close(winnerReturned)
		return &brute.BruteResult{ConnectionSuccess: true, AuthSuccess: true}
	})
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(2, sink, 1, 2)
	wp.noStats, wp.stopOnSuccess = true, true
	passwords := writeWordlist(t, "winner", "hold")
	output := t.TempDir()
	done := make(chan struct{}, 2)
	go func() {
		wp.ProcessHost(first, service, "", "u", passwords, version, 5*time.Second, 1, output, cm, "", nil, false)
		done <- struct{}{}
	}()
	select {
	case <-winnerReturned:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("success worker never overlapped the held attempt")
	}
	go func() {
		wp.ProcessHost(next, service, "", "u", "p", version, 5*time.Second, 1, output, cm, "", nil, false)
		done <- struct{}{}
	}()
	select {
	case <-nextEntered:
		close(release)
		t.Fatal("successful target released slot before joining its held worker")
	case <-time.After(100 * time.Millisecond):
	}
	if _, completed := sink.lifecycle(); completed != 0 {
		close(release)
		t.Fatal("host completed while an attempt was still in flight")
	}
	close(release)
	for range 2 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			wp.Stop()
			t.Fatal("hosts failed to return after the in-flight attempt finished")
		}
	}
	wp.Stop()
	if started, completed := sink.lifecycle(); started != 2 || completed != 2 {
		t.Fatalf("joined success lifecycle = %d/%d, want 2/2", started, completed)
	}
}

func TestProcessHostInterruptedHostDoesNotComplete(t *testing.T) {
	const service = "retirement-interrupted"
	entered, release := make(chan struct{}), make(chan struct{})
	brute.Register(service, func(_ string, _ int, _, _ string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		close(entered)
		<-release
		return &brute.BruteResult{ConnectionSuccess: true}
	})
	host := modules.Host{Host: "127.0.0.1", Port: 45932, Service: service}
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 1, 1)
	wp.noStats = true
	wp.checkpoint = modules.NewCheckpoint("")
	done := make(chan struct{})
	output := t.TempDir()
	go func() {
		defer close(done)
		wp.ProcessHost(host, service, "", "u", "p", version, 2*time.Second, 1, output, cm, "", nil, false)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("worker never entered module")
	}
	stopped := make(chan struct{})
	go func() {
		wp.Stop()
		close(stopped)
	}()
	<-wp.globalStopChan
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted ProcessHost retained a worker")
	}
	<-stopped
	if _, completed := sink.lifecycle(); completed != 0 {
		t.Fatalf("interrupted host emitted %d completions", completed)
	}
	if wp.checkpoint.IsHostCompleted(host.Host, host.Port, service) {
		t.Fatal("interrupted target marked completed")
	}
}

func TestProcessHostRecoveryRetriesOnlyConsumedMissedCredentials(t *testing.T) {
	const service = "retirement-recovery"
	var firstCalls atomic.Int64
	brute.Register(service, func(_ string, _ int, _, password string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		if password == "first" && firstCalls.Add(1) == 1 {
			return &brute.BruteResult{Error: os.ErrDeadlineExceeded}
		}
		return &brute.BruteResult{ConnectionSuccess: true}
	})
	host := modules.Host{Host: "127.0.0.1", Port: 45933, Service: service}
	cb := brute.GetCircuitBreaker()
	key := net.JoinHostPort(host.Host, fmt.Sprint(host.Port))
	cb.Reset(key)
	defer cb.Reset(key)
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(1, sink, 1, 1)
	wp.noStats = true
	wp.checkpoint = modules.NewCheckpoint("")
	passwords := writeWordlist(t, "first", "second")
	wp.ProcessHost(host, service, "", "u", passwords, version, 2*time.Second, 1, t.TempDir(), cm, "", nil, false)
	wp.Stop()
	attempts := sink.attemptResults()
	if len(attempts) != 3 {
		t.Fatalf("base plus recovery attempts = %d, want 3", len(attempts))
	}
	if attempts[0].Password != "first" || attempts[1].Password != "second" ||
		attempts[2].Password != "first" || !attempts[2].Retrying {
		t.Fatalf("recovery order = %#v", attempts)
	}
	if got := wp.checkpoint.GetAttemptedCount(host.Host, host.Port, service); got != 2 {
		t.Fatalf("checkpoint counted %d base attempts, want 2", got)
	}
	if started, completed := sink.lifecycle(); started != 1 || completed != 1 {
		t.Fatalf("recovery lifecycle = %d/%d, want 1/1", started, completed)
	}
}

func TestProcessHostAuthenticationFailuresDoNotRetireLiveTarget(t *testing.T) {
	const service = "retirement-auth-rejection"
	var calls atomic.Int64
	brute.Register(service, func(_ string, _ int, _, _ string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		calls.Add(1)
		return &brute.BruteResult{ConnectionSuccess: true}
	})
	host := modules.Host{Host: "127.0.0.1", Port: 45935, Service: service}
	cb := brute.GetCircuitBreaker()
	key := net.JoinHostPort(host.Host, fmt.Sprint(host.Port))
	oldThreshold, oldDisabled := cb.GetThreshold(), cb.IsDisabled()
	cb.Reset(key)
	cb.SetThreshold(10)
	cb.SetDisabled(false)
	defer func() {
		cb.Reset(key)
		cb.SetThreshold(oldThreshold)
		cb.SetDisabled(oldDisabled)
	}()
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(30, sink, 1, 1)
	wp.noStats = true
	passwords := writeWordlist(t, "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15")
	// 2s module deadline: the mock returns immediately, but a 1ms budget
	// can expire inside RunWithTimeout under full-suite load and would
	// turn an auth rejection into a fake connection failure.
	wp.ProcessHost(host, service, "", "u", passwords, version, 2*time.Second, 1, t.TempDir(), cm, "", nil, false)
	wp.Stop()
	if got := calls.Load(); got != 16 {
		t.Fatalf("authentication failures consumed %d credentials, want all 16", got)
	}
	if cb.IsTripped(key) {
		t.Fatal("authentication rejections tripped the connection-failure breaker")
	}
	if started, completed := sink.lifecycle(); started != 1 || completed != 1 {
		t.Fatalf("live target lifecycle = %d/%d, want 1/1", started, completed)
	}
}
