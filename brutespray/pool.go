package brutespray

import (
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

// Credential represents a single credential attempt
type Credential struct {
	Host     modules.Host
	User     string
	Password string
	Service  string
	Params   brute.ModuleParams
	Retry    bool
}

// HostWorkerPool manages workers for a specific host
type HostWorkerPool struct {
	host           modules.Host
	workers        int
	targetWorkers  int
	currentWorkers int32
	jobQueue       chan Credential
	eventSink      tui.EventSink
	wg             sync.WaitGroup
	stopChan       chan struct{}
	stopOnce       sync.Once
	// Stop-on-success: close stopChan when first credential succeeds
	stopOnSuccess bool
	foundSuccess  int32 // atomic flag
	// Per-host rate limiting (nil = unlimited)
	rateTicker *time.Ticker
	// Adaptive backoff: consecutive connection failures trigger increasing delays
	consecutiveConnFails int64 // atomic
	// Performance tracking for dynamic adjustment
	avgResponseTime time.Duration
	successRate     float64
	totalAttempts   int64
	mutex           sync.RWMutex
	// Pause/resume support
	pauseCh chan struct{}
	paused  bool
	pauseMu sync.Mutex
	// Session log for resume replay
	sessionLog *modules.SessionLog
	checkpoint *modules.Checkpoint
	// Missed credential recovery: credentials that failed due to connection errors
	missedQueue []Credential
	missedMu    sync.Mutex
	// User enumeration skip: users confirmed non-existent by the service (e.g. FTP 530)
	skipUsers sync.Map // user string → struct{}
	// terminal marks a finished pool: the dynamic scaler must not Add()
	// new workers onto a closed queue / a WaitGroup whose Wait is already
	// running (issue #378 lifecycle race). Guarded by mutex together with
	// every wg.Add in Start/scaleTo, so a close that takes the lock can
	// never interleave with an Add.
	terminal bool
	// Shared lockout scheduler owned by WorkerPool.
	budgetScheduler *BudgetScheduler
}

// markTerminal stops the dynamic scaler from adding workers to this pool.
// Call before close(jobQueue) and whenever ProcessHost abandons a pool.
func (hwp *HostWorkerPool) markTerminal() {
	hwp.mutex.Lock()
	hwp.terminal = true
	hwp.mutex.Unlock()
}

// WorkerPool manages the worker goroutines for brute force attempts with per-host allocation
type WorkerPool struct {
	globalWorkers   int
	threadsPerHost  int
	hostPools       map[string]*HostWorkerPool
	hostPoolsMutex  sync.RWMutex
	eventSink       tui.EventSink
	globalStopChan  chan struct{}
	globalStopOnce  sync.Once
	hostParallelism int
	hostSem         chan struct{}
	// Dynamic thread allocation
	dynamicAllocation bool
	minThreadsPerHost int
	maxThreadsPerHost int
	// Statistics control
	noStats        bool
	scalerStop     chan struct{}
	scalerStopOnce sync.Once
	// Stop-on-success: skip remaining credentials for a host after first success
	stopOnSuccess bool
	// Per-host rate limiting (attempts per second; 0 = unlimited)
	rateLimit float64
	// Spray mode: iterate passwords first, users second
	sprayMode        bool
	sprayDelay       time.Duration
	scheduleMode     string
	routeDiagnostics bool
	// Checkpoint for resume capability
	checkpoint *modules.Checkpoint
	// Session log for resume replay
	sessionLog *modules.SessionLog
	// Extra credential options
	useReversedPass bool
	passwordGen     *modules.PasswordGenerator
	// SSH bad-keys pre-pass control
	noBadKeys   bool
	badKeysOnly bool
	// RDP pre-auth recon control
	noRDPScan bool
	// Inline credential pairs from --creds / -c
	inlineCreds     string
	budgetScheduler *BudgetScheduler
	// processedTargets holds one entry per target (poolKey) this run has
	// ever started driving. Duplicate targets from overlapping sources are
	// ignored for the WHOLE run — a re-claim after completion would emit a
	// phantom HostStartedMsg against a stopped pool (issue #378: hosts
	// appearing to start again after being skipped).
	processedTargets sync.Map
	// roundRobin, when non-nil, interleaves credential queueing across
	// hosts in round-robin order (-schedule round-robin, issue #150).
	roundRobin *hostTurnScheduler
}

// PlanTargets records target order for the round-robin rotation so the
// interleave follows the operator's target order. No-op unless
// -schedule round-robin is active.
func (wp *WorkerPool) PlanTargets(hosts []modules.Host) {
	if wp.roundRobin == nil {
		return
	}
	for _, h := range hosts {
		wp.roundRobin.plan(poolKey(h))
	}
}

// NewHostWorkerPool creates a new host-specific worker pool
func NewHostWorkerPool(host modules.Host, workers int, eventSink tui.EventSink, stopOnSuccess bool, rateLimit float64) *HostWorkerPool {
	hwp := &HostWorkerPool{
		host:          host,
		workers:       workers,
		targetWorkers: workers,
		jobQueue:      make(chan Credential, workers*10), // Smaller buffer per host
		eventSink:     eventSink,
		stopChan:      make(chan struct{}),
		stopOnSuccess: stopOnSuccess,
	}
	if rateLimit > 0 {
		interval := time.Duration(float64(time.Second) / rateLimit)
		hwp.rateTicker = time.NewTicker(interval)
	}
	return hwp
}

// NewWorkerPool creates a new worker pool with per-host thread allocation
func NewWorkerPool(threadsPerHost int, eventSink tui.EventSink, hostParallelism int, hostCount int) *WorkerPool {
	// Calculate total workers across all hosts (no capping)
	totalWorkers := threadsPerHost * hostCount

	return &WorkerPool{
		globalWorkers:     totalWorkers,
		threadsPerHost:    threadsPerHost,
		hostPools:         make(map[string]*HostWorkerPool),
		eventSink:         eventSink,
		globalStopChan:    make(chan struct{}),
		hostParallelism:   hostParallelism,
		hostSem:           make(chan struct{}, hostParallelism),
		dynamicAllocation: true,
		minThreadsPerHost: 1,
		maxThreadsPerHost: threadsPerHost * 2,
		scalerStop:        make(chan struct{}),
	}
}

// SetBudgetScheduler applies one shared lockout scheduler across all host pools.
func (wp *WorkerPool) SetBudgetScheduler(scheduler *BudgetScheduler) {
	wp.hostPoolsMutex.Lock()
	defer wp.hostPoolsMutex.Unlock()
	wp.budgetScheduler = scheduler
	for _, hostPool := range wp.hostPools {
		hostPool.budgetScheduler = scheduler
	}
}

func (hwp *HostWorkerPool) reserveBudgetAt(cred Credential, domain string, now time.Time) time.Duration {
	if hwp.budgetScheduler == nil {
		return 0
	}
	return hwp.budgetScheduler.Reserve(NewAttemptIdentity(cred.Service, domain, cred.User), now)
}

func (hwp *HostWorkerPool) waitForBudget(cred Credential, domain string) bool {
	for {
		delay := hwp.reserveBudgetAt(cred, domain, time.Now())
		if delay <= 0 {
			return false
		}
		select {
		case <-time.After(delay):
		case <-hwp.stopChan:
			return true
		}
	}
}

// Start starts the host-specific worker pool with staggered first attempts so
// workers don't all hit the target at the same instant (avoids chunked output).
// It is additive and idempotent: it only spawns until currentWorkers reaches
// workers, so a scaler tick that already added some workers between
// ResetForRetry and Start cannot double the pool. wg.Add happens under mutex
// so it can never race a markTerminal/close (issue #378).
func (hwp *HostWorkerPool) Start(timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	stagger := time.Duration(0)
	if hwp.workers > 1 {
		stagger = timeout / time.Duration(hwp.workers)
		stagger = min(stagger, time.Second)
	}
	hwp.mutex.Lock()
	if hwp.terminal {
		hwp.mutex.Unlock()
		return
	}
	for spawned := int(atomic.LoadInt32(&hwp.currentWorkers)); spawned < hwp.workers; spawned++ {
		hwp.wg.Add(1)
		atomic.AddInt32(&hwp.currentWorkers, 1)
		initialDelay := time.Duration(spawned) * stagger
		go hwp.worker(timeout, retry, output, cm, domain, noStats, initialDelay)
	}
	hwp.mutex.Unlock()
}

// scaleTo adjusts the number of workers towards target. It can only add workers; reducing
// happens cooperatively when workers finish a job and see they are above target.
// The terminal check and the wg.Add loop share hwp.mutex with
// markTerminal/ResetForRetry, so the 2-second scaler tick can never Add a
// worker after the queue was closed and wg.Wait started (issue #378).
func (hwp *HostWorkerPool) scaleTo(newTarget int, timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	hwp.mutex.Lock()
	if hwp.terminal {
		hwp.mutex.Unlock()
		return
	}
	if newTarget < 1 {
		newTarget = 1
	}
	hwp.targetWorkers = newTarget
	// Add workers if below target
	for int(atomic.LoadInt32(&hwp.currentWorkers)) < newTarget {
		hwp.wg.Add(1)
		atomic.AddInt32(&hwp.currentWorkers, 1)
		go hwp.worker(timeout, retry, output, cm, domain, noStats, 0)
	}
	hwp.mutex.Unlock()
}

// Start starts all host worker pools
func (wp *WorkerPool) Start(timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	// Store noStats for use in ProcessHost
	wp.noStats = noStats
	// Host worker pools are started individually when hosts are processed
	// Launch a scaler that periodically adjusts per-host worker counts
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-wp.scalerStop:
				return
			case <-wp.globalStopChan:
				return
			case <-ticker.C:
				wp.hostPoolsMutex.RLock()
				for _, hp := range wp.hostPools {
					target := wp.calculateOptimalThreadsForPool(hp)
					hp.scaleTo(target, timeout, retry, output, cm, domain, noStats)
				}
				wp.hostPoolsMutex.RUnlock()
			}
		}
	}()
}

// Stop stops the host-specific worker pool. The terminal mark and the
// stopChan close happen under hwp.mutex, atomically with respect to every
// wg.Add in Start/scaleTo and to ResetForRetry, so a pool being torn down
// can never be handed new workers (issue #378).
func (hwp *HostWorkerPool) Stop() {
	hwp.mutex.Lock()
	hwp.terminal = true
	hwp.stopOnce.Do(func() { close(hwp.stopChan) })
	hwp.mutex.Unlock()
	hwp.wg.Wait()
	if hwp.rateTicker != nil {
		hwp.rateTicker.Stop()
	}
}

// Stop stops all host worker pools immediately
func (wp *WorkerPool) Stop() {
	alreadyStopped := true
	wp.globalStopOnce.Do(func() {
		alreadyStopped = false
		close(wp.globalStopChan)
	})
	if alreadyStopped {
		return
	}

	// Stop scaler
	wp.scalerStopOnce.Do(func() { close(wp.scalerStop) })

	// Stop all host pools concurrently for faster shutdown
	wp.hostPoolsMutex.RLock()
	var stopWg sync.WaitGroup
	for _, hostPool := range wp.hostPools {
		stopWg.Add(1)
		go func(hp *HostWorkerPool) {
			defer stopWg.Done()
			hp.Stop()
		}(hostPool)
	}
	wp.hostPoolsMutex.RUnlock()

	// Wait for all host pools to stop, but with a timeout to prevent hanging
	done := make(chan struct{})
	go func() {
		stopWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All stopped cleanly
	case <-time.After(2 * time.Second):
		// Force exit after timeout
		modules.TUIError("[!] Force stopping after timeout\n")
	}
}

// Pause pauses all workers for this host. Workers block until Resume is called.
func (hwp *HostWorkerPool) Pause() {
	hwp.pauseMu.Lock()
	defer hwp.pauseMu.Unlock()
	if !hwp.paused {
		hwp.paused = true
		hwp.pauseCh = make(chan struct{})
	}
}

// Resume unblocks all paused workers for this host.
func (hwp *HostWorkerPool) Resume() {
	hwp.pauseMu.Lock()
	defer hwp.pauseMu.Unlock()
	if hwp.paused {
		hwp.paused = false
		close(hwp.pauseCh)
	}
}

// waitIfPaused blocks the caller until the host is resumed or stopped.
// Returns true if the host was stopped while paused (caller should exit).
func (hwp *HostWorkerPool) waitIfPaused() bool {
	hwp.pauseMu.Lock()
	if !hwp.paused {
		hwp.pauseMu.Unlock()
		return false
	}
	ch := hwp.pauseCh
	hwp.pauseMu.Unlock()

	select {
	case <-ch: // resumed
		return false
	case <-hwp.stopChan: // stopped while paused
		return true
	}
}

// PauseHost pauses worker pools whose key matches hostKey ("ip:port") or
// any service-scoped variant ("ip:port/service") for that address.
func (wp *WorkerPool) PauseHost(hostKey string) {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	for k, hp := range wp.hostPools {
		if k == hostKey || strings.HasPrefix(k, hostKey+"/") {
			hp.Pause()
		}
	}
}

// ResumeHost resumes worker pools for hostKey ("ip:port"), including all
// service-scoped pools at that address.
func (wp *WorkerPool) ResumeHost(hostKey string) {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	for k, hp := range wp.hostPools {
		if k == hostKey || strings.HasPrefix(k, hostKey+"/") {
			hp.Resume()
		}
	}
}

// PauseAll pauses all host worker pools.
func (wp *WorkerPool) PauseAll() {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	for _, hp := range wp.hostPools {
		hp.Pause()
	}
}

// ResumeAll resumes all host worker pools.
func (wp *WorkerPool) ResumeAll() {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	for _, hp := range wp.hostPools {
		hp.Resume()
	}
}

// SetThreadsPerHost updates the threads-per-host setting. Existing pools
// will rescale on the next scaler tick.
func (wp *WorkerPool) SetThreadsPerHost(n int) {
	if n < 1 {
		n = 1
	}
	wp.hostPoolsMutex.Lock()
	wp.threadsPerHost = n
	wp.maxThreadsPerHost = n * 2
	wp.hostPoolsMutex.Unlock()
}

// SetHostParallelism updates the host parallelism (semaphore size).
func (wp *WorkerPool) SetHostParallelism(n int) {
	if n < 1 {
		n = 1
	}
	wp.hostPoolsMutex.Lock()
	wp.hostParallelism = n
	// Replace the semaphore channel with new capacity
	newSem := make(chan struct{}, n)
	// Transfer existing tokens (up to new capacity)
	for {
		select {
		case tok := <-wp.hostSem:
			select {
			case newSem <- tok:
			default:
				// New capacity is smaller; drop excess tokens
			}
		default:
			goto done
		}
	}
done:
	wp.hostSem = newSem
	wp.hostPoolsMutex.Unlock()
}

// GetThreadsPerHost returns the current threads-per-host setting.
func (wp *WorkerPool) GetThreadsPerHost() int {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	return wp.threadsPerHost
}

// GetHostParallelism returns the current host parallelism setting.
func (wp *WorkerPool) GetHostParallelism() int {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	return wp.hostParallelism
}

// worker is the main worker goroutine for host-specific worker pool
func (hwp *HostWorkerPool) worker(timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool, initialDelay time.Duration) {
	defer hwp.wg.Done()

	// Stagger the first attempt so workers don't all hit the target at once
	if initialDelay > 0 {
		select {
		case <-time.After(initialDelay):
		case <-hwp.stopChan:
			atomic.AddInt32(&hwp.currentWorkers, -1)
			return
		}
	}

	for {
		// Block if host is paused
		if hwp.waitIfPaused() {
			atomic.AddInt32(&hwp.currentWorkers, -1)
			return
		}

		// If scaling down and queue appears empty, allow this worker to exit
		hwp.mutex.RLock()
		target := hwp.targetWorkers
		hwp.mutex.RUnlock()
		if int(atomic.LoadInt32(&hwp.currentWorkers)) > target {
			select {
			case <-hwp.stopChan:
				atomic.AddInt32(&hwp.currentWorkers, -1)
				return
			default:
				// Only exit if no job immediately available
				select {
				case <-hwp.stopChan:
					atomic.AddInt32(&hwp.currentWorkers, -1)
					return
				case cred, ok := <-hwp.jobQueue:
					if !ok {
						atomic.AddInt32(&hwp.currentWorkers, -1)
						return
					}
					hwp.processCredential(cred, timeout, retry, output, cm, domain, noStats)
					continue
				default:
					atomic.AddInt32(&hwp.currentWorkers, -1)
					return
				}
			}
		}
		select {
		case <-hwp.stopChan:
			atomic.AddInt32(&hwp.currentWorkers, -1)
			return
		case cred, ok := <-hwp.jobQueue:
			if !ok {
				atomic.AddInt32(&hwp.currentWorkers, -1)
				return
			}
			hwp.processCredential(cred, timeout, retry, output, cm, domain, noStats)
		}
	}
}

// applyAdaptiveBackoff waits with exponential backoff when a host has
// consecutive connection failures. Returns true if the host pool was stopped
// during the wait (caller should return).
//
// When the circuit breaker is ENABLED the failure-budget admission in
// brute.CircuitBreaker.AdmitDial is the pacing: it admits at most
// `threshold` real failures before tripping and queues the rest. Adding the
// old pre-dial sleep on top double-paces the same host and made the skip
// threshold itself unreachable in reasonable time — a single-thread run
// against a dead host slept 2+4+8+16+30s between dials and needed ~3
// minutes to log 10 connection errors (issue #366: "it dosnt stop bruting
// after 10 or 20 conn error"). With the breaker enabled the sleep is
// therefore skipped. With `-skip-policy off` (breaker disabled, never
// trips, no budget) the legacy backoff still applies unchanged.
func (hwp *HostWorkerPool) applyAdaptiveBackoff(cred Credential) bool {
	fails := atomic.LoadInt64(&hwp.consecutiveConnFails)
	if fails <= 0 {
		return false
	}
	hostKey := net.JoinHostPort(cred.Host.Host, strconv.Itoa(cred.Host.Port))
	cb := brute.GetCircuitBreaker()
	// Once the circuit breaker has tripped, attempts short-circuit without
	// touching the network; sleeping 30s per queued credential just stalls
	// the host instead of finishing it (issue #366: looked like "still
	// bruting" long after the skip).
	if cb.IsTripped(hostKey) {
		return false
	}
	if !cb.IsDisabled() {
		return false
	}
	backoff := time.Duration(1<<uint(fails)) * time.Second
	backoff = min(backoff, 30*time.Second)
	if fails >= 3 {
		if modules.TUIMode {
			modules.TUIError("[*] %s — backing off %v (%d consecutive connection failures)\n", hostKey, backoff, fails)
		} else {
			modules.PrintfColored(pterm.FgYellow, "[*] %s — backing off %v (%d consecutive connection failures)\n", hostKey, backoff, fails)
		}
	}
	select {
	case <-time.After(backoff):
		return false
	case <-hwp.stopChan:
		return true
	}
}

func (hwp *HostWorkerPool) processCredential(cred Credential, timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	// Skip users that the service confirmed don't exist (e.g. FTP 530)
	if _, skipped := hwp.skipUsers.Load(cred.User); skipped {
		return
	}

	// Issue #366 (report 2026-11-23): once the breaker tripped, the skip
	// policy declared this host done. Drain the remaining queued
	// credentials WITHOUT a per-credential event or network attempt — they
	// never touch the wire, and emitting each one made a skipped host look
	// like it was "still bruting" in the TUI (the (169)/(230) counters in
	// the operator's screenshot were mostly these phantom rows).
	hostKey := net.JoinHostPort(cred.Host.Host, strconv.Itoa(cred.Host.Port))
	if brute.GetCircuitBreaker().IsTripped(hostKey) {
		if hwp.checkpoint != nil && !cred.Retry {
			hwp.checkpoint.RecordAttemptForHost(cred.Host.Host, cred.Host.Port, cred.Service)
		}
		// Count the credential in the progress tracker without an attempt
		// row, so legacy mode's "N/M combinations tested" still completes.
		// The TUI ignores ProgressEvent; only LegacyEventSink consumes it.
		hwp.eventSink.Send(tui.ProgressEvent{Retry: cred.Retry})
		return
	}

	// Random jitter to prevent workers from re-synchronizing after completing
	// jobs with similar response times. Scale jitter with timeout.
	maxJitter := timeout / 10
	maxJitter = min(maxJitter, 500*time.Millisecond)
	if maxJitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(maxJitter))))
	}

	if hwp.applyAdaptiveBackoff(cred) {
		return
	}

	// Rate limiting: wait for ticker before proceeding
	if hwp.rateTicker != nil {
		select {
		case <-hwp.rateTicker.C:
		case <-hwp.stopChan:
			return
		}
	}

	if hwp.waitForBudget(cred, domain) {
		return
	}

	// Track performance for dynamic adjustment
	startTime := time.Now()

	// Execute the brute force attempt
	result := brute.RunBrute(cred.Host, cred.User, cred.Password, timeout, retry, output, "", "", domain, cm, cred.Params)

	// Record statistics (if enabled) — only count connection errors, not auth failures
	duration := time.Since(startTime)
	if !noStats {
		if !result.ConnectionSuccess && result.Status != brute.StatusSkippedService {
			modules.RecordConnectionError(cred.Host.Host)
		}
	}

	// Propagate user skip (e.g. FTP 530 user-not-found)
	if result.SkipUser {
		hwp.skipUsers.Store(cred.User, struct{}{})
	}

	// Update adaptive backoff counter
	if result.ConnectionSuccess {
		atomic.StoreInt64(&hwp.consecutiveConnFails, 0)
	} else {
		atomic.AddInt64(&hwp.consecutiveConnFails, 1)
		// Record missed credential for retry pass — but never credentials
		// the circuit breaker skipped locally: those never touched the
		// network, and replaying them re-hammers a host the operator
		// already gave up on (issue #366 retry storm).
		if result.Status != brute.StatusSkippedService {
			hwp.missedMu.Lock()
			hwp.missedQueue = append(hwp.missedQueue, cred)
			hwp.missedMu.Unlock()
		}
	}

	// Stop-on-success: signal host pool to stop processing remaining credentials
	if result.AuthSuccess && hwp.stopOnSuccess {
		if atomic.CompareAndSwapInt32(&hwp.foundSuccess, 0, 1) {
			hwp.stopOnce.Do(func() { close(hwp.stopChan) })
		}
	}

	// Update performance metrics
	hwp.updatePerformanceMetrics(result.AuthSuccess, duration)
	if hwp.checkpoint != nil && !cred.Retry {
		hwp.checkpoint.RecordAttemptForHost(cred.Host.Host, cred.Host.Port, cred.Service)
	}
	modules.WriteDebugAttempt(cred.Service, cred.Host.Host, cred.Host.Port, cred.User, cred.Password, string(result.Status), result.ConnectionSuccess, cred.Retry, duration, result.Error)

	// Send structured event to the UI layer
	hwp.eventSink.Send(tui.AttemptResultMsg{
		Host:      cred.Host.Host,
		Port:      cred.Host.Port,
		Service:   cred.Service,
		User:      cred.User,
		Password:  cred.Password,
		Success:   result.AuthSuccess,
		Connected: result.ConnectionSuccess,
		Error:     result.Error,
		Duration:  duration,
		Retrying:  cred.Retry,
		Status:    string(result.Status),
		Timestamp: startTime,
		Banner:    result.Banner,
		KeyMatch:  result.KeyMatch,
	})

	// Write to session log for resume replay
	if hwp.sessionLog != nil {
		hwp.sessionLog.Write(modules.SessionEntry{
			Type:      "attempt",
			Host:      cred.Host.Host,
			Port:      cred.Host.Port,
			Service:   cred.Service,
			User:      cred.User,
			Password:  cred.Password,
			Success:   result.AuthSuccess,
			Connected: result.ConnectionSuccess,
			Retrying:  cred.Retry,
			Status:    string(result.Status),
			Duration:  duration,
			Timestamp: startTime,
		})
	}
}

// updatePerformanceMetrics updates the performance metrics for the host
func (hwp *HostWorkerPool) updatePerformanceMetrics(success bool, responseTime time.Duration) {
	hwp.mutex.Lock()
	defer hwp.mutex.Unlock()

	hwp.totalAttempts++

	// Update average response time using exponential moving average
	if hwp.totalAttempts == 1 {
		hwp.avgResponseTime = responseTime
	} else {
		alpha := 0.1
		hwp.avgResponseTime = time.Duration(float64(hwp.avgResponseTime)*(1-alpha) + float64(responseTime)*alpha)
	}

	// Update success rate
	if success {
		hwp.successRate = (hwp.successRate*float64(hwp.totalAttempts-1) + 1.0) / float64(hwp.totalAttempts)
	} else {
		hwp.successRate = hwp.successRate * float64(hwp.totalAttempts-1) / float64(hwp.totalAttempts)
	}
}

// ResetForRetry resets the host worker pool state so it can be reused for a
// retry pass. This clears stop-on-success state, worker counts, backoff
// counters, and skip lists that would otherwise cause retried credentials to
// be silently dropped. The fresh stopChan/stopOnce and jobQueue are
// installed under the same mutex that guards the terminal flag and every
// wg.Add: no observer can see a non-terminal pool holding the previous
// generation's closed queue or closed stop channel (issue #378).
func (hwp *HostWorkerPool) ResetForRetry() {
	atomic.StoreInt64(&hwp.consecutiveConnFails, 0)
	hwp.skipUsers = sync.Map{}
	hwp.missedMu.Lock()
	hwp.missedQueue = nil
	hwp.missedMu.Unlock()
	hwp.mutex.Lock()
	hwp.stopChan = make(chan struct{})
	hwp.stopOnce = sync.Once{}
	hwp.jobQueue = make(chan Credential, hwp.workers*10)
	atomic.StoreInt32(&hwp.foundSuccess, 0)
	atomic.StoreInt32(&hwp.currentWorkers, 0)
	hwp.terminal = false
	hwp.mutex.Unlock()
}

// DrainMissedQueue returns and clears the missed credential queue for this host.
func (hwp *HostWorkerPool) DrainMissedQueue() []Credential {
	hwp.missedMu.Lock()
	defer hwp.missedMu.Unlock()
	missed := hwp.missedQueue
	hwp.missedQueue = nil
	return missed
}

// AddJob adds a credential to the appropriate host's job queue
func (wp *WorkerPool) AddJob(cred Credential) {
	hostKey := poolKey(cred.Host)

	wp.hostPoolsMutex.RLock()
	hostPool, exists := wp.hostPools[hostKey]
	wp.hostPoolsMutex.RUnlock()

	if !exists {
		// This shouldn't happen if ProcessHost is called first, but handle gracefully
		return
	}

	select {
	case hostPool.jobQueue <- cred:
	case <-hostPool.stopChan:
	case <-wp.globalStopChan:
	}
}

// poolKey is the identity of a target's worker pool: address PLUS service.
// Issue #378: the old address-only key made two different services on one
// host:port share a single jobQueue — the second ProcessHost fed and closed
// a queue the first still owned ("send on closed channel"), silently
// dropping one service's attempts.
func poolKey(host modules.Host) string {
	return net.JoinHostPort(host.Host, strconv.Itoa(host.Port)) + "/" + host.Service
}

// getOrCreateHostPool gets or creates a host-specific worker pool
func (wp *WorkerPool) getOrCreateHostPool(host modules.Host) *HostWorkerPool {
	hostKey := poolKey(host)

	wp.hostPoolsMutex.RLock()
	hostPool, exists := wp.hostPools[hostKey]
	wp.hostPoolsMutex.RUnlock()

	if !exists {
		wp.hostPoolsMutex.Lock()
		// Double-check after acquiring write lock
		if hostPool, exists = wp.hostPools[hostKey]; !exists {
			// Determine threads for this host (could be dynamic based on performance)
			threadsForHost := wp.threadsPerHost
			if wp.dynamicAllocation {
				threadsForHost = wp.calculateOptimalThreadsForHost(host)
			}

			hostPool = NewHostWorkerPool(host, threadsForHost, wp.eventSink, wp.stopOnSuccess, wp.rateLimit)
			hostPool.sessionLog = wp.sessionLog
			hostPool.checkpoint = wp.checkpoint
			hostPool.budgetScheduler = wp.budgetScheduler
			wp.hostPools[hostKey] = hostPool
		}
		wp.hostPoolsMutex.Unlock()
	}

	return hostPool
}

// calculateOptimalThreadsForHost returns the exact threads per host as specified by user
func (wp *WorkerPool) calculateOptimalThreadsForHost(_ modules.Host) int {
	// Backward-compatible default used when not using host pool state
	return wp.threadsPerHost
}

// calculateOptimalThreadsForPool computes a target worker count based on current
// per-host pool performance: faster avg response -> more threads; many errors -> fewer.
func (wp *WorkerPool) calculateOptimalThreadsForPool(hp *HostWorkerPool) int {
	hp.mutex.RLock()
	avg := hp.avgResponseTime
	success := hp.successRate
	attempts := hp.totalAttempts
	hp.mutex.RUnlock()

	target := wp.threadsPerHost
	if attempts < 10 {
		return target
	}

	// Scale with simple rules of thumb
	// Very fast responses (<200ms) -> double threads (up to max)
	if avg < 200*time.Millisecond {
		target = wp.threadsPerHost * 2
	} else if avg > 2*time.Second {
		// Slow responses -> halve threads (down to min)
		target = wp.threadsPerHost / 2
		target = max(target, 1)
	}

	// If success rate high, reduce retries via speed-up threads modestly
	if success > 0.25 {
		target += wp.threadsPerHost / 2
	}

	if target < wp.minThreadsPerHost {
		target = wp.minThreadsPerHost
	}
	if target > wp.maxThreadsPerHost {
		target = wp.maxThreadsPerHost
	}
	return target
}
