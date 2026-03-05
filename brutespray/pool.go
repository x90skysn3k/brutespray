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
)

// Credential represents a single credential attempt
type Credential struct {
	Host     modules.Host
	User     string
	Password string
	Service  string
}

// HostWorkerPool manages workers for a specific host
type HostWorkerPool struct {
	host           modules.Host
	workers        int
	targetWorkers  int
	currentWorkers int32
	jobQueue       chan Credential
	progressCh     chan int
	wg             sync.WaitGroup
	stopChan       chan struct{}
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
}

// WorkerPool manages the worker goroutines for brute force attempts with per-host allocation
type WorkerPool struct {
	globalWorkers   int
	threadsPerHost  int
	hostPools       map[string]*HostWorkerPool
	hostPoolsMutex  sync.RWMutex
	progressCh      chan int
	globalStopChan  chan struct{}
	hostParallelism int
	hostSem         chan struct{}
	// Dynamic thread allocation
	dynamicAllocation bool
	minThreadsPerHost int
	maxThreadsPerHost int
	// Statistics control
	noStats    bool
	scalerStop chan struct{}
	// Stop-on-success: skip remaining credentials for a host after first success
	stopOnSuccess bool
	// Per-host rate limiting (attempts per second; 0 = unlimited)
	rateLimit float64
	// Spray mode: iterate passwords first, users second
	sprayMode  bool
	sprayDelay time.Duration
	// Checkpoint for resume capability
	checkpoint *modules.Checkpoint
}

// NewHostWorkerPool creates a new host-specific worker pool
func NewHostWorkerPool(host modules.Host, workers int, progressCh chan int, stopOnSuccess bool, rateLimit float64) *HostWorkerPool {
	hwp := &HostWorkerPool{
		host:          host,
		workers:       workers,
		targetWorkers: workers,
		jobQueue:      make(chan Credential, workers*10), // Smaller buffer per host
		progressCh:    progressCh,
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
func NewWorkerPool(threadsPerHost int, progressCh chan int, hostParallelism int, hostCount int) *WorkerPool {
	// Calculate total workers across all hosts (no capping)
	totalWorkers := threadsPerHost * hostCount

	return &WorkerPool{
		globalWorkers:     totalWorkers,
		threadsPerHost:    threadsPerHost,
		hostPools:         make(map[string]*HostWorkerPool),
		progressCh:        progressCh,
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
	hwp.mutex.Unlock()
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
	select {
	case <-hwp.stopChan:
		// Already stopped
		return
	default:
		close(hwp.stopChan)
	}
	hwp.wg.Wait()
	if hwp.rateTicker != nil {
		hwp.rateTicker.Stop()
	}
}

// Stop stops all host worker pools immediately
func (wp *WorkerPool) Stop() {
	// Close global stop channel first to signal all operations to stop
	select {
	case <-wp.globalStopChan:
		// Already stopped
		return
	default:
		close(wp.globalStopChan)
	}

	// Stop scaler
	select {
	case <-wp.scalerStop:
	default:
		close(wp.scalerStop)
	}

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
		fmt.Println("[!] Force stopping after timeout")
	}
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

	// Adaptive backoff: when a host has many consecutive connection failures,
	// back off before trying again. Escalates: 2s, 4s, 8s, 16s, capped at 30s.
	fails := atomic.LoadInt64(&hwp.consecutiveConnFails)
	if fails > 0 {
		backoff := time.Duration(1<<uint(fails)) * time.Second
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		if fails >= 3 {
			hostKey := fmt.Sprintf("%s:%d", cred.Host.Host, cred.Host.Port)
			modules.PrintfColored(pterm.FgYellow, "[*] %s — backing off %v (%d consecutive connection failures)\n", hostKey, backoff, fails)
		}
		select {
		case <-time.After(backoff):
		case <-hwp.stopChan:
			return
		}
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
	result := brute.RunBrute(cred.Host, cred.User, cred.Password, hwp.progressCh, timeout, retry, output, "", "", domain, cm)

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
	}

	// Stop-on-success: signal host pool to stop processing remaining credentials
	if result.AuthSuccess && hwp.stopOnSuccess {
		if atomic.CompareAndSwapInt32(&hwp.foundSuccess, 0, 1) {
			select {
			case <-hwp.stopChan:
			default:
				close(hwp.stopChan)
			}
		}
	}

	// Update performance metrics
	hwp.updatePerformanceMetrics(result.AuthSuccess, duration)
	// progressCh may be closed during shutdown; recover from the panic.
	func() {
		defer func() { recover() }()
		hwp.progressCh <- 1
	}()
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

			hostPool = NewHostWorkerPool(host, threadsForHost, wp.progressCh, wp.stopOnSuccess, wp.rateLimit)
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
