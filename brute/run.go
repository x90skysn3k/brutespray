package brute

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// sanitizeCred strips CR/LF and null bytes from a credential string to prevent
// protocol injection in text-based services (AMI, TeamSpeak, VMAuthd, NNTP, etc.).
func sanitizeCred(s string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(s)
}

// AttemptStatus classifies a credential attempt beyond the legacy success
// booleans. Existing callers still use AuthSuccess and ConnectionSuccess; the
// status gives retry, debug, JSONL, and checkpoint paths a stable reason code.
type AttemptStatus string

const (
	StatusAuthSuccess        AttemptStatus = "auth_success"
	StatusAuthFailure        AttemptStatus = "auth_failure"
	StatusConnectionFailure  AttemptStatus = "connection_failure"
	StatusUnsupportedService AttemptStatus = "unsupported_service"
	StatusSkippedService     AttemptStatus = "skipped_service"
	StatusModulePanic        AttemptStatus = "module_panic_recovered"
	StatusModuleTimeout      AttemptStatus = "module_timeout"
	StatusAnyPassword        AttemptStatus = "any_password"
)

// ConfirmAnyPassword controls the hit-confirmation probe: after a module
// reports an authentication success, RunBrute re-plays the attempt with a
// random password. Servers that accept the random password too are
// accepts-any-password devices (embedded junk); the "hit" is demoted to a
// WARN finding instead of a credential success. Set false via
// -no-confirm-hits. Password-auth only; key/badkey/wrapper attempts skip it.
var ConfirmAnyPassword = true

func classifyAttemptStatus(result *BruteResult) AttemptStatus {
	if result == nil {
		return StatusConnectionFailure
	}
	if result.Status != "" {
		return result.Status
	}
	if result.AuthSuccess {
		return StatusAuthSuccess
	}
	if result.ConnectionSuccess {
		if result.Status == StatusAnyPassword {
			return StatusAnyPassword
		}
		return StatusAuthFailure
	}
	return StatusConnectionFailure
}

func resultWithStatus(result *BruteResult) BruteResult {
	if result == nil {
		return BruteResult{Status: StatusConnectionFailure}
	}
	result.Status = classifyAttemptStatus(result)
	return *result
}

// BruteResult captures the outcome of a single credential attempt including
// whether the connection itself succeeded (to distinguish auth failures from
// network failures).
type BruteResult struct {
	AuthSuccess       bool
	ConnectionSuccess bool
	Status            AttemptStatus // stable classified result code
	Error             error         // underlying error for diagnostics
	Banner            string        // service banner if captured
	RetryDelay        time.Duration // if > 0, module requests this delay before next retry (e.g. VNC anti-brute)
	SkipUser          bool          // if true, skip remaining passwords for this user (e.g. FTP 530 user-not-found)
	Finding           *Finding      // pre-auth recon result, nil if none
	KeyMatch          *KeyMatch     // SSH bad-key match, nil if none
	Proof
}

// EnsureProof fills default proof metadata for credential-auth results.
func (r *BruteResult) EnsureProof(service string) {
	if r == nil {
		return
	}
	if r.Confidence == "" {
		if r.AuthSuccess && r.ConnectionSuccess {
			r.Confidence = ConfidenceConfirmed
		} else {
			r.Confidence = ConfidenceInconclusive
		}
	}
	if r.ProofType == "" {
		if r.KeyMatch != nil {
			r.ProofType = ProofBadKey
		} else {
			r.ProofType = ProofAuthProtocolSuccess
		}
	}
	if r.Detail == "" && service != "" {
		r.Detail = service + " module result"
	}
}

// confirmProbeApplicable decides whether an apparent auth success is worth a
// random-password re-check. Skipped for modules where the password is not a
// plain secret: SSH key auth, the bad-keys marker, and the wrapper module
// (re-running an operator command with junk input could have side effects).
func confirmProbeApplicable(service, user, password string, params ModuleParams) bool {
	if service == "wrapper" || service == "smtpvrfy" {
		return false
	}
	if strings.HasPrefix(password, badKeyMarker) {
		return false
	}
	if kp, ok := params["key"]; ok && kp != "" && kp != "false" {
		return false
	}
	return true
}

// randomProbePassword builds a high-entropy password that no real default or
// wordlist entry would match.
func randomProbePassword() string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%"
	b := make([]byte, 20)
	if _, err := cryptorand.Read(b); err != nil {
		// crypto/rand cannot realistically fail here; fall back to a
		// static impossible-looking probe value rather than skipping
		// confirmation entirely.
		return "xZ9!confirm-probe-unlikely-password"
	}
	out := make([]byte, 0, len(b)+4)
	out = append(out, "xZ9!"...)
	for _, v := range b {
		out = append(out, charset[int(v)%len(charset)])
	}
	return string(out)
}

// CircuitBreaker tracks connection failures per host since the last
// successful authentication and trips (skips further attempts) after a
// threshold is reached. Connection successes with rejected credentials do
// NOT clear the counter; only an authentication success does.
type CircuitBreaker struct {
	mu               sync.RWMutex
	consecutiveFails map[string]*int64 // host:port -> consecutive failure count
	tripped          map[string]bool   // host:port -> tripped
	threshold        int64             // consecutive failures before tripping
	disabled         bool              // when true, never trips
}

// DefaultCircuitBreakerThreshold is the number of connection failures since
// the last successful authentication before a host is considered
// uncooperative and further attempts are skipped.
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

// SetDisabled controls whether the circuit breaker is active.
func (cb *CircuitBreaker) SetDisabled(disabled bool) {
	cb.mu.Lock()
	cb.disabled = disabled
	cb.mu.Unlock()
}

// SetThreshold updates how many consecutive connection failures trip the
// breaker. Values below 1 are coerced to 1 to keep RecordFailure deterministic.
func (cb *CircuitBreaker) SetThreshold(threshold int64) {
	if threshold < 1 {
		threshold = 1
	}
	cb.mu.Lock()
	cb.threshold = threshold
	cb.mu.Unlock()
}

// IsTripped returns true if the host has been marked unreachable.
// Always returns false when the circuit breaker is disabled.
func (cb *CircuitBreaker) IsTripped(hostKey string) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	if cb.disabled {
		return false
	}
	return cb.tripped[hostKey]
}

// RecordFailure increments the consecutive failure counter for a host and
// trips the breaker if the threshold is reached. Returns true if tripped.
func (cb *CircuitBreaker) RecordFailure(hostKey string) bool {
	cb.mu.Lock()
	if cb.disabled {
		cb.mu.Unlock()
		return false
	}
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

// RecordSuccess clears the failure counter for a host after a successful
// authentication.
func (cb *CircuitBreaker) RecordSuccess(hostKey string) {
	cb.mu.Lock()
	if counter, ok := cb.consecutiveFails[hostKey]; ok {
		atomic.StoreInt64(counter, 0)
	}
	cb.mu.Unlock()
}

func runModuleWithBoundary(fn BruteFunc, service string, host string, port int, user string, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	if timeout <= 0 {
		timeout = time.Second
	}
	resultCh := make(chan *BruteResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- &BruteResult{
					AuthSuccess:       false,
					ConnectionSuccess: false,
					Status:            StatusModulePanic,
					Error:             fmt.Errorf("module %s panic: %v", service, r),
				}
			}
		}()
		resultCh <- fn(host, port, user, password, timeout, cm, params)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result == nil {
			return &BruteResult{
				AuthSuccess:       false,
				ConnectionSuccess: false,
				Status:            StatusConnectionFailure,
				Error:             fmt.Errorf("module %s returned nil result", service),
			}
		}
		return result
	case <-timer.C:
		return &BruteResult{
			AuthSuccess:       false,
			ConnectionSuccess: false,
			Status:            StatusModuleTimeout,
			Error:             fmt.Errorf("module %s timed out after %v", service, timeout),
		}
	}
}

// Reset clears the circuit breaker state for a host.
func (cb *CircuitBreaker) Reset(hostKey string) {
	cb.mu.Lock()
	delete(cb.consecutiveFails, hostKey)
	delete(cb.tripped, hostKey)
	cb.mu.Unlock()
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

func RunBrute(h modules.Host, u string, p string, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string, domain string, cm *modules.ConnectionManager, params ModuleParams) BruteResult {
	service := h.Service

	// Start performance monitoring
	startTime := time.Now()
	metrics := modules.GetGlobalMetrics()

	hostKey := net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
	cb := GetCircuitBreaker()

	// Check circuit breaker before attempting
	if cb.IsTripped(hostKey) {
		metrics.RecordAttempt(false, time.Since(startTime))
		modules.RecordAttempt(false)
		return BruteResult{AuthSuccess: false, ConnectionSuccess: false, Status: StatusSkippedService}
	}

	// Build effective params: merge domain and https into params if not already set
	effectiveParams := make(ModuleParams)
	for k, v := range params {
		effectiveParams[k] = v
	}
	if effectiveParams["domain"] == "" && domain != "" {
		effectiveParams["domain"] = domain
	}
	if effectiveParams["https"] == "" && (service == "https" || service == "https-form") {
		effectiveParams["https"] = "true"
	}

	// Parse domain from user (DOMAIN\user format)
	effectiveUser := u
	if effectiveParams["domain"] == "" && strings.Contains(u, "\\") {
		parts := strings.SplitN(u, "\\", 2)
		if len(parts) == 2 {
			effectiveParams["domain"] = parts[0]
			effectiveUser = parts[1]
		}
	}

	retries := 0
	var modResult *BruteResult

	for {
		if retries >= maxRetries {
			// Record failed attempt (connection never succeeded)
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return BruteResult{AuthSuccess: false, ConnectionSuccess: false, Status: StatusConnectionFailure}
		}

		// Calculate backoff delay (decoupled from timeout)
		delayTime := calculateBackoff(retries)

		fn, ok := Lookup(service)
		if !ok {
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return BruteResult{AuthSuccess: false, ConnectionSuccess: false, Status: StatusUnsupportedService}
		}

		modResult = runModuleWithBoundary(fn, service, h.Host, h.Port, effectiveUser, p, timeout, cm, effectiveParams)

		// Hit confirmation (issue #366): accepts-any-password servers
		// produce bogus hits that also reset the circuit breaker on every
		// "success". Re-verify with a random password; a second success
		// means the device opens for anything.
		if modResult != nil && modResult.AuthSuccess && modResult.ConnectionSuccess &&
			ConfirmAnyPassword && confirmProbeApplicable(service, effectiveUser, p, effectiveParams) {
			probePassword := randomProbePassword()
			probe := runModuleWithBoundary(fn, service, h.Host, h.Port, effectiveUser, probePassword, timeout, cm, effectiveParams)
			if probe != nil && probe.AuthSuccess && probe.ConnectionSuccess {
				modResult.AuthSuccess = false
				modResult.Status = StatusAnyPassword
				modResult.Finding = &Finding{
					Severity: "WARN",
					Code:     "any-password",
					Message:  fmt.Sprintf("Server accepted credential %q and a random password; it likely authenticates any credential (not a usable hit)", p),
					Proof: Proof{
						Confidence: ConfidenceConfirmed,
						ProofType:  ProofAuthProtocolSuccess,
						Detail:     "confirmation probe: random password also accepted",
					},
				}
				modules.WriteFindingWithProof("WARN", "any-password", service, h.Host, h.Port,
					modResult.Finding.Message, "", string(ConfidenceConfirmed), string(ProofAuthProtocolSuccess),
					"confirmation probe: random password also accepted")
			}
		}

		modResult.Status = classifyAttemptStatus(modResult)
		modResult.EnsureProof(service)

		result := modResult.AuthSuccess
		con_result := modResult.ConnectionSuccess

		if con_result {
			// Connection succeeded — record attempt. The breaker is NOT
			// cleared here: a reachable host that rejects credentials
			// (e.g. RDP ErrKindAuth) returns ConnectionSuccess=true, so
			// resetting on connection success let interleaved auth
			// failures indefinitely defer the skip policy on live-but-
			// uncooperative hosts (issue #366). Only a successful
			// authentication clears the connection-failure counter.
			metrics.RecordAttempt(result, time.Since(startTime))
			modules.RecordAttempt(result)

			if result {
				// Authentication succeeded — host is healthy; reset breaker
				cb.RecordSuccess(hostKey)
				modules.RecordSuccess(service, h.Host, h.Port, u, p, time.Since(startTime), modResult.Banner)
				if modResult.KeyMatch != nil {
					modules.PrintBadKeyResult(service, h.Host, h.Port, u,
						modResult.KeyMatch.Vendor, modResult.KeyMatch.CVE, modResult.KeyMatch.Description)
				}
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

			modules.PrintResultWithStatusAndProof(service, h.Host, h.Port, u, p, result, con_result, willRetry, output, delayTime, string(modResult.Status), string(modResult.Confidence), string(modResult.ProofType), modResult.Detail)

			if willRetry {
				// Use module-requested delay if set (e.g. VNC anti-brute)
				if modResult.RetryDelay > 0 && modResult.RetryDelay > delayTime {
					modules.PrintfColored(0, "[*] %s anti-brute-force detected, sleeping %v\n", service, modResult.RetryDelay)
					time.Sleep(modResult.RetryDelay)
				} else {
					time.Sleep(delayTime)
				}
			} else {
				// Either exhausted retries or circuit breaker tripped
				metrics.RecordAttempt(false, time.Since(startTime))
				modules.RecordAttempt(false)
				return resultWithStatus(modResult)
			}
		}
	}

	modules.PrintResultWithStatusAndProof(service, h.Host, h.Port, u, p, modResult.AuthSuccess, modResult.ConnectionSuccess, false, output, 0, string(modResult.Status), string(modResult.Confidence), string(modResult.ProofType), modResult.Detail, modResult.Banner)
	return BruteResult{
		AuthSuccess:       modResult.AuthSuccess,
		ConnectionSuccess: modResult.ConnectionSuccess,
		Status:            modResult.Status,
		Error:             modResult.Error,
		Banner:            modResult.Banner,
		SkipUser:          modResult.SkipUser,
		Finding:           modResult.Finding,
		KeyMatch:          modResult.KeyMatch,
		Proof:             modResult.Proof,
	}
}
