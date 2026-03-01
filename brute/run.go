package brute

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

// BruteResult captures the outcome of a single credential attempt including
// whether the connection itself succeeded (to distinguish auth failures from
// network failures).
type BruteResult struct {
	AuthSuccess       bool
	ConnectionSuccess bool
}

// CircuitBreaker tracks consecutive connection failures per host and trips
// (skips further attempts) after a threshold is reached.
type CircuitBreaker struct {
	mu                sync.RWMutex
	consecutiveFails  map[string]*int64 // host:port -> consecutive failure count
	tripped           map[string]bool   // host:port -> tripped
	threshold         int64             // consecutive failures before tripping
}

// DefaultCircuitBreakerThreshold is the number of consecutive connection
// failures before a host is considered unreachable and further attempts are
// skipped.
const DefaultCircuitBreakerThreshold = 5

var globalCircuitBreaker = &CircuitBreaker{
	consecutiveFails: make(map[string]*int64),
	tripped:          make(map[string]bool),
	threshold:        DefaultCircuitBreakerThreshold,
}

// GetCircuitBreaker returns the global circuit breaker instance.
func GetCircuitBreaker() *CircuitBreaker {
	return globalCircuitBreaker
}

// IsTripped returns true if the host has been marked unreachable.
func (cb *CircuitBreaker) IsTripped(hostKey string) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.tripped[hostKey]
}

// RecordFailure increments the consecutive failure counter for a host and
// trips the breaker if the threshold is reached. Returns true if tripped.
func (cb *CircuitBreaker) RecordFailure(hostKey string) bool {
	cb.mu.Lock()
	counter, ok := cb.consecutiveFails[hostKey]
	if !ok {
		var c int64
		counter = &c
		cb.consecutiveFails[hostKey] = counter
	}
	cb.mu.Unlock()

	newVal := atomic.AddInt64(counter, 1)
	if newVal >= cb.threshold {
		cb.mu.Lock()
		if !cb.tripped[hostKey] {
			cb.tripped[hostKey] = true
			cb.mu.Unlock()
			return true // just tripped
		}
		cb.mu.Unlock()
	}
	return false
}

// RecordSuccess resets the consecutive failure counter for a host.
func (cb *CircuitBreaker) RecordSuccess(hostKey string) {
	cb.mu.Lock()
	if counter, ok := cb.consecutiveFails[hostKey]; ok {
		atomic.StoreInt64(counter, 0)
	}
	cb.mu.Unlock()
}

// Reset clears the circuit breaker state for a host.
func (cb *CircuitBreaker) Reset(hostKey string) {
	cb.mu.Lock()
	delete(cb.consecutiveFails, hostKey)
	delete(cb.tripped, hostKey)
	cb.mu.Unlock()
}

func ClearMaps() {
	// Deprecated: Maps are now local to RunBrute
}

// baseRetryDelay is used for backoff calculations, decoupled from the
// connection timeout so that retry delays stay short.
const baseRetryDelay = 500 * time.Millisecond

// calculateBackoff calculates exponential backoff with jitter using a fixed
// base delay rather than the connection timeout.
func calculateBackoff(retryCount int) time.Duration {
	if retryCount == 0 {
		return baseRetryDelay
	}

	// Exponential backoff: 2^retryCount * base
	backoff := baseRetryDelay * time.Duration(1<<uint(retryCount))

	// Cap at 5 seconds
	if backoff > 5*time.Second {
		backoff = 5 * time.Second
	}

	// Add jitter (±25%)
	factor := 1 + (rand.Float64()*0.5 - 0.25)
	backoff = time.Duration(float64(backoff) * factor)

	return backoff
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string, domain string, cm *modules.ConnectionManager) BruteResult {
	service := h.Service
	var result, con_result bool

	// Start performance monitoring
	startTime := time.Now()
	metrics := modules.GetGlobalMetrics()

	hostKey := fmt.Sprintf("%s:%d", h.Host, h.Port)
	cb := GetCircuitBreaker()

	// Check circuit breaker before attempting
	if cb.IsTripped(hostKey) {
		metrics.RecordAttempt(false, time.Since(startTime))
		modules.RecordAttempt(false)
		return BruteResult{AuthSuccess: false, ConnectionSuccess: false}
	}

	retries := 0

	for {
		if retries >= maxRetries {
			// Record failed attempt (connection never succeeded)
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}

		// Calculate backoff delay (decoupled from timeout)
		delayTime := calculateBackoff(retries)

		switch service {
		case "ssh":
			result, con_result = BruteSSH(h.Host, h.Port, u, p, timeout, cm)
		case "ftp":
			result, con_result = BruteFTP(h.Host, h.Port, u, p, timeout, cm)
		case "mssql":
			result, con_result = BruteMSSQL(h.Host, h.Port, u, p, timeout, cm)
		case "telnet":
			result, con_result = BruteTelnet(h.Host, h.Port, u, p, timeout, cm)
		case "smbnt":
			parsedUser := u
			parsedDomain := domain
			if parsedDomain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteSMB(h.Host, h.Port, parsedUser, p, timeout, cm, parsedDomain)
		case "postgres":
			result, con_result = BrutePostgres(h.Host, h.Port, u, p, timeout, cm)
		case "smtp":
			result, con_result = BruteSMTP(h.Host, h.Port, u, p, timeout, cm)
		case "imap":
			result, con_result = BruteIMAP(h.Host, h.Port, u, p, timeout, cm)
		case "pop3":
			result, con_result = BrutePOP3(h.Host, h.Port, u, p, timeout, cm)
		case "snmp":
			result, con_result = BruteSNMP(h.Host, h.Port, u, p, timeout, cm)
		case "mysql":
			result, con_result = BruteMYSQL(h.Host, h.Port, u, p, timeout, cm)
		case "vmauthd":
			result, con_result = BruteVMAuthd(h.Host, h.Port, u, p, timeout, cm)
		case "asterisk":
			result, con_result = BruteAsterisk(h.Host, h.Port, u, p, timeout, cm)
		case "vnc":
			result, con_result = BruteVNC(h.Host, h.Port, u, p, timeout, cm)
		case "mongodb":
			result, con_result = BruteMongoDB(h.Host, h.Port, u, p, timeout, cm)
		case "nntp":
			result, con_result = BruteNNTP(h.Host, h.Port, u, p, timeout, cm)
		case "oracle":
			result, con_result = BruteOracle(h.Host, h.Port, u, p, timeout, cm)
		case "teamspeak":
			result, con_result = BruteTeamSpeak(h.Host, h.Port, u, p, timeout, cm)
		case "xmpp":
			result, con_result = BruteXMPP(h.Host, h.Port, u, p, timeout, cm)
		case "rdp":
			parsedUser := u
			parsedDomain := domain
			if domain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteRDP(h.Host, h.Port, parsedUser, p, timeout, cm, parsedDomain)
		case "redis":
			result, con_result = BruteRedis(h.Host, h.Port, u, p, timeout, cm)
		case "http":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, cm)
		case "https":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, cm)
		default:
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}

		if con_result {
			// Connection succeeded — reset circuit breaker and record attempt
			cb.RecordSuccess(hostKey)
			metrics.RecordAttempt(result, time.Since(startTime))
			modules.RecordAttempt(result)

			if result {
				// Authentication succeeded
				modules.RecordSuccess(service, h.Host, h.Port, u, p, time.Since(startTime))
			} else {
				// Authentication failed
				modules.RecordError(false) // Authentication error
			}

			break
		} else {
			// Connection failed: increment the consecutive failure counter
			retries++

			// Record in circuit breaker — may trip
			if justTripped := cb.RecordFailure(hostKey); justTripped {
				modules.PrintfColored(0, "[!] Circuit breaker tripped for %s — skipping remaining credentials\n", hostKey)
			}

			willRetry := retries < maxRetries && !cb.IsTripped(hostKey)

			// Record connection error
			metrics.RecordError(true)

			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, willRetry, output, delayTime)

			if willRetry {
				time.Sleep(delayTime)
			} else {
				// Either exhausted retries or circuit breaker tripped
				metrics.RecordAttempt(false, time.Since(startTime))
				modules.RecordAttempt(false)
				return BruteResult{AuthSuccess: false, ConnectionSuccess: false}
			}
		}
	}

	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, false, output, 0)
	return BruteResult{AuthSuccess: result, ConnectionSuccess: con_result}
}

func WaitForSkipsToComplete() {
	// Deprecated: Scaling logic handles cleanup
}
