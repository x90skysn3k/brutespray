package brutespray

import (
	"fmt"
	"math/rand"
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
	// Missed credential recovery: credentials that failed due to connection errors
	missedQueue []Credential
	missedMu    sync.Mutex
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
	sprayMode  bool
	sprayDelay time.Duration
	// Checkpoint for resume capability
	checkpoint *modules.Checkpoint
	// Session log for resume replay
	sessionLog *modules.SessionLog
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

// Start starts the host-specific worker pool with staggered first attempts so
// workers don't all hit the target at the same instant (avoids chunked output).
func (hwp *HostWorkerPool) Start(timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	stagger := time.Duration(0)
	if hwp.workers > 1 {
		stagger = timeout / time.Duration(hwp.workers)
		if stagger > time.Second {
			stagger = time.Second
		}
	}
	for i := 0; i < hwp.workers; i++ {
		hwp.wg.Add(1)
		atomic.AddInt32(&hwp.currentWorkers, 1)
		initialDelay := time.Duration(i) * stagger
		go hwp.worker(timeout, retry, output, cm, domain, noStats, initialDelay)
	}
}

// scaleTo adjusts the number of workers towards target. It can only add workers; reducing
// happens cooperatively when workers finish a job and see they are above target.
func (hwp *HostWorkerPool) scaleTo(newTarget int, timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, noStats bool) {
	if newTarget < 1 {
		newTarget = 1
	}
	hwp.mutex.Lock()
	hwp.targetWorkers = newTarget
	hwp.mutex.Unlock() // safe: no panicking code between lock/unlock
	// Add workers if below target
	for int(atomic.LoadInt32(&hwp.currentWorkers)) < newTarget {
		hwp.wg.Add(1)
		atomic.AddInt32(&hwp.currentWorkers, 1)
		go hwp.worker(timeout, retry, output, cm, domain, noStats, 0)
	}
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

// Stop stops the host-specific worker pool
func (hwp *HostWorkerPool) Stop() {
	hwp.stopOnce.Do(func() { close(hwp.stopChan) })
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

// PauseHost pauses workers for a specific host.
func (wp *WorkerPool) PauseHost(hostKey string) {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	if hp, ok := wp.hostPools[hostKey]; ok {
		hp.Pause()
	}
}

// ResumeHost resumes workers for a specific host.
func (wp *WorkerPool) ResumeHost(hostKey string) {
	wp.hostPoolsMutex.RLock()
	defer wp.hostPoolsMutex.RUnlock()
	if hp, ok := wp.hostPools[hostKey]; ok {
		hp.Resume()
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
func (hwp *HostWorkerPool) applyAdaptiveBackoff(cred Credential) bool {
	fails := atomic.LoadInt64(&hwp.consecutiveConnFails)
	if fails <= 0 {
		return false
	}
	backoff := time.Duration(1<<uint(fails)) * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	if fails >= 3 {
		hostKey := fmt.Sprintf("%s:%d", cred.Host.Host, cred.Host.Port)
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
	// Random jitter to prevent workers from re-synchronizing after completing
	// jobs with similar response times. Scale jitter with timeout.
	maxJitter := timeout / 10
	if maxJitter > 500*time.Millisecond {
		maxJitter = 500 * time.Millisecond
	}
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

	// Track performance for dynamic adjustment
	startTime := time.Now()

	// Execute the brute force attempt
	result := brute.RunBrute(cred.Host, cred.User, cred.Password, timeout, retry, output, "", "", domain, cm, cred.Params)

	// Record statistics (if enabled) — only count connection errors, not auth failures
	duration := time.Since(startTime)
	if !noStats {
		if !result.ConnectionSuccess {
			modules.RecordConnectionError(cred.Host.Host)
		}
	}

	// Update adaptive backoff counter
	if result.ConnectionSuccess {
		atomic.StoreInt64(&hwp.consecutiveConnFails, 0)
	} else {
		atomic.AddInt64(&hwp.consecutiveConnFails, 1)
		// Record missed credential for retry pass
		hwp.missedMu.Lock()
		hwp.missedQueue = append(hwp.missedQueue, cred)
		hwp.missedMu.Unlock()
	}

	// Stop-on-success: signal host pool to stop processing remaining credentials
	if result.AuthSuccess && hwp.stopOnSuccess {
		if atomic.CompareAndSwapInt32(&hwp.foundSuccess, 0, 1) {
			hwp.stopOnce.Do(func() { close(hwp.stopChan) })
		}
	}

	// Update performance metrics
	hwp.updatePerformanceMetrics(result.AuthSuccess, duration)

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
		Timestamp: startTime,
		Banner:    result.Banner,
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
	hostKey := fmt.Sprintf("%s:%d", cred.Host.Host, cred.Host.Port)

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

// getOrCreateHostPool gets or creates a host-specific worker pool
func (wp *WorkerPool) getOrCreateHostPool(host modules.Host) *HostWorkerPool {
	hostKey := fmt.Sprintf("%s:%d", host.Host, host.Port)

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
			wp.hostPools[hostKey] = hostPool
		}
		wp.hostPoolsMutex.Unlock()
	}

	return hostPool
}

// calculateOptimalThreadsForHost returns the exact threads per host as specified by user
func (wp *WorkerPool) calculateOptimalThreadsForHost(host modules.Host) int {
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
		if target < 1 {
			target = 1
		}
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
