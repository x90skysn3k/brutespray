package brutespray

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

// BadKeyCred is a synthetic user/password pair for the SSH bad-keys pre-pass.
// Password carries the marker "::badkey::N" where N indexes into the bundle;
// BruteSSH unpacks this marker (see brute/ssh.go:badKeyMarker).
type BadKeyCred struct {
	User     string
	Password string
}

// BuildBadKeyCreds turns the embedded bad-keys bundle into a list of synthetic
// credential pairs. When userOverride is set (operator passed -u explicitly),
// every pair uses that username; otherwise each entry's metadata-suggested
// user is used (root for F5, vagrant for Vagrant, etc.).
func BuildBadKeyCreds(bundle []badkeys.Entry, userOverride string) []BadKeyCred {
	out := make([]BadKeyCred, 0, len(bundle))
	for i, e := range bundle {
		u := e.Username
		if userOverride != "" {
			u = userOverride
		}
		out = append(out, BadKeyCred{
			User:     u,
			Password: fmt.Sprintf("::badkey::%d", i),
		})
	}
	return out
}

// ParseInlineCreds parses "user:pass,user2:pass2" form into BadKeyCred-shaped
// pairs (reusing the same struct for symmetry with the bad-keys path).
// Splits each pair on the FIRST colon so passwords containing colons survive.
func ParseInlineCreds(s string) []BadKeyCred {
	if s == "" {
		return nil
	}
	var out []BadKeyCred
	for _, part := range strings.Split(s, ",") {
		idx := strings.Index(part, ":")
		if idx < 0 {
			continue
		}
		out = append(out, BadKeyCred{User: part[:idx], Password: part[idx+1:]})
	}
	return out
}

// reverseString returns the reversed version of a string.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// emitFinding routes a pre-auth recon finding through the output layer
// (text/JSONL/TUI) via modules.WriteFindingWithProof.
func emitFinding(host modules.Host, f *brute.Finding) {
	if f == nil {
		return
	}
	f.EnsureProof()
	modules.WriteFindingWithProof(f.Severity, f.Code, host.Service, host.Host, host.Port, f.Message, f.CVE, string(f.Confidence), string(f.ProofType), f.Detail)
}

func collectPreAuthFindings(ctx context.Context, host modules.Host, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) []*brute.Finding {
	probes := brute.PreAuthProbes(host.Service)
	if len(probes) == 0 {
		return nil
	}
	target := brute.PreAuthTarget{
		Service: host.Service,
		Host:    host.Host,
		Port:    host.Port,
		Timeout: timeout,
		CM:      cm,
		Params:  params,
	}
	var findings []*brute.Finding
	for _, probe := range probes {
		if !probe.Default {
			continue
		}
		probeFindings, err := probe.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pre-auth probe %s %s: %v\n", probe.Code, target.Address(), err)
			continue
		}
		for i := range probeFindings {
			finding := probeFindings[i]
			findings = append(findings, &finding)
		}
	}
	return findings
}

// queueForHost enqueues one credential on the host pool's job queue,
// honoring round-robin turn order when a scheduler is installed
// (-schedule round-robin, issue #150) and the per-host/global stop
// channels. Returns false when queueing was abandoned (caller returns).
//
// Round-robin rule: exactly one credential per host per rotation. A host
// whose queue buffer is full marks itself stalled while it blocks on the
// send, so the rotation skips it instead of deadlocking behind a slow or
// paused host; it rejoins as soon as the send completes.
func (wp *WorkerPool) queueForHost(hostPool *HostWorkerPool, pk string, cred Credential) bool {
	select {
	case <-hostPool.stopChan:
		return false
	case <-wp.globalStopChan:
		return false
	default:
	}
	if rr := wp.roundRobin; rr != nil {
		if !rr.waitTurn(pk, hostPool.stopChan, wp.globalStopChan) {
			return false
		}
		// Fast path: queue has room, hand the turn over immediately.
		select {
		case hostPool.jobQueue <- cred:
			rr.advance(pk)
			return true
		default:
		}
		// Queue full: stall this host while blocked so the rotation can
		// move on to the other hosts.
		rr.stall(pk)
		var ok bool
		select {
		case hostPool.jobQueue <- cred:
			ok = true
		case <-hostPool.stopChan:
		case <-wp.globalStopChan:
		}
		rr.unstall(pk)
		if ok {
			rr.advance(pk)
		}
		return ok
	}
	select {
	case hostPool.jobQueue <- cred:
		return true
	case <-hostPool.stopChan:
		return false
	case <-wp.globalStopChan:
		return false
	}
}

// queueHostCredentials is ProcessHost's queueing phase: it generates every credential for one host
// (combo mode, single-secret services, or the user×password schedules, plus inline creds and the
// SSH bad-keys pre-pass) and queues them on the host pool, honoring the resume cursor and the
// per-host/global stop channels. It returns wordlistFailed: true when a wordlist load errored, in
// which case ProcessHost requests a stop and skips host completion. Every other exit — normal
// completion, a stop signal, queue abandonment, or the --badkeys-only short-circuit — returns
// false, exactly as the previous inline closure only set wordlistFailed on load errors.
func (wp *WorkerPool) queueHostCredentials(hostPool *HostWorkerPool, pk string, host modules.Host, service string, combo string, user string, password string, version string, moduleParams brute.ModuleParams, useUsernameAsPass bool, cursor *resumeCursor) bool {
	// Generate and queue all credentials for this host
	if combo != "" {
		users, passwords := modules.GetUsersAndPasswordsCombo(&host, combo, version)
		n := len(users)
		n = min(n, len(passwords))
		for i := 0; i < n; i++ {
			if cursor.skipNext() {
				continue
			}
			// Check if we should stop before processing each credential
			select {
			case <-wp.globalStopChan:
				return false
			case <-hostPool.stopChan:
				return false
			default:
			}

			cred := Credential{
				Host:     host,
				User:     users[i],
				Password: passwords[i],
				Service:  service,
				Params:   moduleParams,
			}
			if !wp.queueForHost(hostPool, pk, cred) {
				return false
			}
		}
	} else {
		if modules.IsSingleSecretService(service, moduleParams) {
			queuePassword := func(p string) bool {
				// Check if we should stop before processing each credential
				select {
				case <-wp.globalStopChan:
					return false
				case <-hostPool.stopChan:
					return false
				default:
				}

				if cursor.skipNext() {
					return true
				}
				cred := Credential{
					Host:     host,
					User:     "",
					Password: p,
					Service:  service,
					Params:   moduleParams,
				}
				return wp.queueForHost(hostPool, pk, cred)
			}

			if wp.inlineCreds != "" {
				for _, pair := range ParseInlineCreds(wp.inlineCreds) {
					if !queuePassword(pair.Password) {
						return false
					}
				}
			}

			var passwords []string
			if wp.passwordGen != nil {
				passwords = wp.passwordGen.Generate()
			} else {
				_, pw, err := modules.GetUsersAndPasswords(&host, user, password, version)
				if err != nil {
					modules.TUIError("Error loading wordlist for %s: %v\n", service, err)
					return true
				}
				passwords = pw
			}
			for _, p := range passwords {
				if !queuePassword(p) {
					return false
				}
			}
		} else {
			var users, passwords []string
			if wp.passwordGen != nil {
				// Only load users from wordlist; passwords come from generator
				u, _, err := modules.GetUsersAndPasswords(&host, user, password, version)
				if err != nil {
					modules.TUIError("Error loading wordlist for %s: %v\n", service, err)
					return true
				}
				users = u
				passwords = wp.passwordGen.Generate()
			} else {
				u, p, err := modules.GetUsersAndPasswords(&host, user, password, version)
				if err != nil {
					modules.TUIError("Error loading wordlist for %s: %v\n", service, err)
					return true
				}
				users = u
				passwords = p
			}

			queueCred := func(u, p string) bool {
				select {
				case <-wp.globalStopChan:
					return false
				case <-hostPool.stopChan:
					return false
				default:
				}
				if cursor.skipNext() {
					return true
				}
				cred := Credential{Host: host, User: u, Password: p, Service: service, Params: moduleParams}
				return wp.queueForHost(hostPool, pk, cred)
			}

			// Inline credential pairs from --creds / -c — fire first across ALL services.
			if wp.inlineCreds != "" {
				for _, p := range ParseInlineCreds(wp.inlineCreds) {
					if !queueCred(p.User, p.Password) {
						return false
					}
				}
			}

			// SSH bad-keys pre-pass: try the embedded bundle before any password list.
			// Opt-out via --no-badkeys; --badkeys-only short-circuits the regular loop.
			if service == "ssh" && !wp.noBadKeys {
				// effectiveBadKeyUser is the username to apply across the bad-keys pre-pass.
				// When -u is a file path (wordlist), we cannot use a single value — fall back
				// to each entry's metadata-suggested user. When -u is a bare username, use it
				// as the override.
				effectiveBadKeyUser := ""
				if user != "" {
					if _, statErr := os.Stat(user); statErr != nil {
						// Not a file → treat as a bare username
						effectiveBadKeyUser = user
					}
				}
				if bundle, err := badkeys.Load(); err == nil {
					for _, pair := range BuildBadKeyCreds(bundle, effectiveBadKeyUser) {
						if !queueCred(pair.User, pair.Password) {
							return false
						}
					}
				} else {
					fmt.Fprintf(os.Stderr, "warning: bad-keys bundle load failed (skipping pre-pass): %v\n", err)
				}
			}

			if service == "ssh" && wp.badKeysOnly {
				// This is a complete credential source, not an abandoned host.
				return false
			}

			scheduleMode := wp.scheduleMode
			if scheduleMode == "" || scheduleMode == "auto" {
				if wp.sprayMode {
					scheduleMode = "spray"
				} else {
					scheduleMode = "host-major"
				}
			}

			if scheduleMode == "spray" {
				// Spray: try each password across all users before next password

				// Prepend username-as-password round if -e s
				if useUsernameAsPass {
					for _, u := range users {
						if !queueCred(u, u) {
							return false
						}
					}
				}

				// Prepend reversed-username round if -e r
				if wp.useReversedPass {
					for _, u := range users {
						reversed := reverseString(u)
						if reversed != u { // skip if palindrome (already covered by -e s)
							if !queueCred(u, reversed) {
								return false
							}
						}
					}
				}

				for i, p := range passwords {
					if wp.sprayMode && i > 0 && wp.sprayDelay > 0 {
						modules.PrintfColored(pterm.FgLightYellow, "[spray] %s — waiting %v before next password round...\n", host.Host, wp.sprayDelay)
						select {
						case <-time.After(wp.sprayDelay):
						case <-wp.globalStopChan:
							return false
						case <-hostPool.stopChan:
							return false
						}
					}
					for _, u := range users {
						if !queueCred(u, p) {
							return false
						}
					}
				}
			} else {
				pairs := credentialPairs(users, passwords, credentialOrderOptions{
					mode:              scheduleMode,
					sprayMode:         wp.sprayMode,
					useUsernameAsPass: useUsernameAsPass,
					useReversedPass:   wp.useReversedPass,
				})
				for pair := range pairs {
					if !queueCred(pair.User, pair.Password) {
						return false
					}
				}
			}
		}
	}
	return false
}

// ProcessHost processes a single host with all its credentials using dedicated host worker pool
func (wp *WorkerPool) ProcessHost(host modules.Host, service string, combo string, user string, password string, version string, timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string, moduleParams brute.ModuleParams, useUsernameAsPass bool) {
	// One driver per target, for the whole run (issue #378). cfg.Hosts is
	// deduplicated at config time, but overlapping sources and scanner
	// files can still deliver the same target twice; a second ProcessHost
	// for one target would Start/feed/close the same HostWorkerPool queue
	// (double close / send-on-closed-channel / duplicate brute force) or,
	// after completion, emit a phantom HostStartedMsg against a stopped
	// pool. Duplicates are dropped before any event is emitted.
	pk := poolKey(host)
	if _, seen := wp.processedTargets.LoadOrStore(pk, struct{}{}); seen {
		return
	}
	if wp.roundRobin != nil {
		// Fallback for every abandonment path; the queueing tail calls
		// leave() right after the last credential so finished hosts stop
		// gating the rotation immediately (leave is idempotent).
		defer wp.roundRobin.leave(pk)
	}

	// Skip hosts already completed in a previous run
	if wp.checkpoint != nil && wp.checkpoint.IsHostCompleted(host.Host, host.Port, service) {
		return
	}
	resumeCursor := newResumeCursor(wp.checkpoint, host)

	// Check if we should stop before acquiring semaphore
	select {
	case <-wp.globalStopChan:
		return
	default:
	}

	// Acquire host semaphore to limit concurrent hosts. The limiter is a
	// stable pointer whose limit can be changed online (TUI settings):
	// unlike the previous channel swap, release can never strand behind a
	// replaced object (issue #378).
	sem := wp.hostSem
	if !sem.acquire(wp.globalStopChan) {
		return
	}
	defer sem.release()

	// Check again after acquiring semaphore
	select {
	case <-wp.globalStopChan:
		return
	default:
	}

	// Get or create host-specific worker pool
	hostPool := wp.getOrCreateHostPool(host)
	// Every exit joins workers before the deferred host-slot release.
	defer hostPool.Stop()

	// Start the host worker pool
	hostPool.Start(timeout, retry, output, cm, domain, wp.noStats)

	// Notify TUI of host start
	wp.eventSink.Send(tui.HostStartedMsg{
		Host:    host.Host,
		Port:    host.Port,
		Service: host.Service,
		Threads: hostPool.workers,
	})

	// Write host start to session log for resume replay
	if wp.sessionLog != nil {
		wp.sessionLog.Write(modules.SessionEntry{
			Type:      "host_started",
			Host:      host.Host,
			Port:      host.Port,
			Service:   host.Service,
			Threads:   hostPool.workers,
			Timestamp: time.Now(),
		})
	}

	// Debug output to show host processing
	modules.PrintfColored(pterm.FgLightGreen, "[*] Processing host: %s:%d (%s) with %d threads\n", host.Host, host.Port, host.Service, hostPool.workers)
	if wp.routeDiagnostics {
		modules.PrintRouteDiagnostic(cm, host.Host, host.Port, host.Service)
	}

	if service != "rdp" || !wp.noRDPScan {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		for _, finding := range collectPreAuthFindings(ctx, host, timeout, cm, moduleParams) {
			emitFinding(host, finding)
		}
		cancel()
	}

	wordlistFailed := wp.queueHostCredentials(hostPool, pk, host, service, combo, user, password, version, moduleParams, useUsernameAsPass, &resumeCursor)

	// Queueing is done: leave the round-robin rotation now so finished
	// hosts stop gating the remaining hosts (leave is idempotent with the
	// ProcessHost defer fallback).
	if wp.roundRobin != nil {
		wp.roundRobin.leave(pk)
	}

	// The producer is the sole queue closer. Stop additions before Wait,
	// including terminal-success and breaker exits from the producer above.
	waitForPass := func() {
		hostPool.markTerminal()
		close(hostPool.jobQueue)
		done := make(chan struct{})
		go func() {
			hostPool.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-wp.globalStopChan:
			hostPool.Stop()
		}
	}
	if wordlistFailed {
		hostPool.requestStop()
	}
	waitForPass()

	select {
	case <-wp.globalStopChan:
		return
	default:
	}
	if wordlistFailed {
		return
	}

	// A terminal policy decision must not be undone by missed recovery.
	missed := hostPool.DrainMissedQueue()
	if brute.GetCircuitBreaker().IsTripped(net.JoinHostPort(host.Host, strconv.Itoa(host.Port))) {
		missed = nil
	}
	select {
	case <-hostPool.stopChan:
		missed = nil
	default:
	}
	if len(missed) > 0 {
		modules.PrintfColored(pterm.FgLightYellow, "[*] Retrying %d missed credentials for %s:%d\n", len(missed), host.Host, host.Port)
		// All workers from the first generation have exited before its
		// queue and stop channel are replaced for the one recovery pass.
		hostPool.ResetForRetry()
		hostPool.Start(timeout, retry, output, cm, domain, wp.noStats)
	retryLoop:
		for _, cred := range missed {
			cred.Retry = true
			select {
			case <-hostPool.stopChan:
				break retryLoop
			case <-wp.globalStopChan:
				break retryLoop
			default:
			}
			select {
			case hostPool.jobQueue <- cred:
			case <-hostPool.stopChan:
				break retryLoop
			case <-wp.globalStopChan:
				break retryLoop
			}
		}
		waitForPass()
	}
	hostPool.Stop()
	select {
	case <-wp.globalStopChan:
		return
	default:
	}

	// Debug output to show host completion with performance metrics
	hostPool.mutex.RLock()
	avgResponseTime := hostPool.avgResponseTime
	successRate := hostPool.successRate
	totalAttempts := hostPool.totalAttempts
	hostPool.mutex.RUnlock()

	// Notify TUI of host completion
	wp.eventSink.Send(tui.HostCompletedMsg{
		Host:          host.Host,
		Port:          host.Port,
		Service:       host.Service,
		TotalAttempts: totalAttempts,
		SuccessRate:   successRate,
		AvgResponseMs: float64(avgResponseTime.Milliseconds()),
	})

	// Write host completion to session log for resume replay
	if wp.sessionLog != nil {
		wp.sessionLog.Write(modules.SessionEntry{
			Type:          "host_completed",
			Host:          host.Host,
			Port:          host.Port,
			Service:       host.Service,
			TotalAttempts: totalAttempts,
			SuccessRate:   successRate,
			AvgResponseMs: float64(avgResponseTime.Milliseconds()),
			Timestamp:     time.Now(),
		})
	}

	modules.PrintfColored(pterm.FgLightGreen, "[*] Completed host: %s:%d (%s) - %d attempts, %.1f%% success, avg %.2fs\n",
		host.Host, host.Port, host.Service, totalAttempts, successRate*100, avgResponseTime.Seconds())

	// Mark host as completed in checkpoint
	if wp.checkpoint != nil {
		wp.checkpoint.MarkHostCompleted(host.Host, host.Port, service)
	}
}
