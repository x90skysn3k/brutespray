package brutespray

import (
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

// ProcessHost processes a single host with all its credentials using dedicated host worker pool
func (wp *WorkerPool) ProcessHost(host modules.Host, service string, combo string, user string, password string, version string, timeout time.Duration, retry int, output string, cm *modules.ConnectionManager, domain string) {
	// Skip hosts already completed in a previous run
	if wp.checkpoint != nil && wp.checkpoint.IsHostCompleted(host.Host, host.Port, service) {
		return
	}

	// Check if we should stop before acquiring semaphore
	select {
	case <-wp.globalStopChan:
		return
	default:
	}

	// Acquire host semaphore to limit concurrent hosts
	select {
	case wp.hostSem <- struct{}{}:
	case <-wp.globalStopChan:
		return
	}
	defer func() { <-wp.hostSem }()

	// Check again after acquiring semaphore
	select {
	case <-wp.globalStopChan:
		return
	default:
	}

	// Get or create host-specific worker pool
	hostPool := wp.getOrCreateHostPool(host)

	// Start the host worker pool
	hostPool.Start(timeout, retry, output, cm, domain, wp.noStats)

	// Notify TUI of host start
	wp.eventSink.Send(tui.HostStartedMsg{
		Host:    host.Host,
		Port:    host.Port,
		Service: host.Service,
		Threads: hostPool.workers,
	})

	// Debug output to show host processing
	modules.PrintfColored(pterm.FgLightGreen, "[*] Processing host: %s:%d (%s) with %d threads\n", host.Host, host.Port, host.Service, hostPool.workers)

	// Generate and queue all credentials for this host
	if combo != "" {
		users, passwords := modules.GetUsersAndPasswordsCombo(&host, combo, version)
		for i := range users {
			// Check if we should stop before processing each credential
			select {
			case <-wp.globalStopChan:
				return
			case <-hostPool.stopChan:
				return
			default:
			}

			cred := Credential{
				Host:     host,
				User:     users[i],
				Password: passwords[i],
				Service:  service,
			}
			select {
			case hostPool.jobQueue <- cred:
			case <-hostPool.stopChan:
				return
			case <-wp.globalStopChan:
				return
			}
		}
	} else {
		if service == "vnc" || service == "snmp" {
			_, passwords, err := modules.GetUsersAndPasswords(&host, user, password, version)
			if err != nil {
				modules.TUIError("Error loading wordlist for %s: %v\n", service, err)
				return
			}
			for _, p := range passwords {
				// Check if we should stop before processing each credential
				select {
				case <-wp.globalStopChan:
					return
				case <-hostPool.stopChan:
					return
				default:
				}

				cred := Credential{
					Host:     host,
					User:     "",
					Password: p,
					Service:  service,
				}
				select {
				case hostPool.jobQueue <- cred:
				case <-hostPool.stopChan:
					return
				case <-wp.globalStopChan:
					return
				}
			}
		} else {
			users, passwords, err := modules.GetUsersAndPasswords(&host, user, password, version)
			if err != nil {
				modules.TUIError("Error loading wordlist for %s: %v\n", service, err)
				return
			}

			queueCred := func(u, p string) bool {
				select {
				case <-wp.globalStopChan:
					return false
				case <-hostPool.stopChan:
					return false
				default:
				}
				cred := Credential{Host: host, User: u, Password: p, Service: service}
				select {
				case hostPool.jobQueue <- cred:
					return true
				case <-hostPool.stopChan:
					return false
				case <-wp.globalStopChan:
					return false
				}
			}

			if wp.sprayMode {
				// Spray: try each password across all users before next password
				for i, p := range passwords {
					if i > 0 && wp.sprayDelay > 0 {
						modules.PrintfColored(pterm.FgLightYellow, "[spray] %s — waiting %v before next password round...\n", host.Host, wp.sprayDelay)
						select {
						case <-time.After(wp.sprayDelay):
						case <-wp.globalStopChan:
							return
						case <-hostPool.stopChan:
							return
						}
					}
					for _, u := range users {
						if !queueCred(u, p) {
							return
						}
					}
				}
			} else {
				// Standard: try all passwords per user
				for _, u := range users {
					for _, p := range passwords {
						if !queueCred(u, p) {
							return
						}
					}
				}
			}
		}
	}

	// Close the job queue to signal no more jobs will be added
	select {
	case <-wp.globalStopChan:
		// If we're stopping, don't close the queue normally, let Stop() handle it
		hostPool.Stop()
		return
	case <-hostPool.stopChan:
		// Host pool already stopped
		return
	default:
		close(hostPool.jobQueue)
	}

	// Wait for all jobs to complete or be interrupted
	done := make(chan struct{})
	go func() {
		hostPool.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All jobs completed normally
	case <-wp.globalStopChan:
		// Interrupted, stop the host pool
		hostPool.Stop()
		return
	case <-hostPool.stopChan:
		// Host pool stopped
		return
	}

	// Now stop the host pool (this will close stopChan but jobQueue is already closed)
	hostPool.Stop()

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

	modules.PrintfColored(pterm.FgLightGreen, "[*] Completed host: %s:%d (%s) - %d attempts, %.1f%% success, avg %.2fs\n",
		host.Host, host.Port, host.Service, totalAttempts, successRate*100, avgResponseTime.Seconds())

	// Mark host as completed in checkpoint
	if wp.checkpoint != nil {
		wp.checkpoint.MarkHostCompleted(host.Host, host.Port, service)
	}
}
