package brutespray

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
	"golang.org/x/term"
)

func configureCircuitBreaker(cfg *Config) {
	policy := cfg.SkipPolicy
	if policy == "" {
		policy = "auto"
	}
	threshold := cfg.MaxConnFails
	if threshold < 1 {
		switch policy {
		case "aggressive":
			threshold = 3
		default:
			threshold = brute.DefaultCircuitBreakerThreshold
		}
	}

	cb := brute.GetCircuitBreaker()
	cb.SetThreshold(int64(threshold))
	cb.SetDisabled(policy == "off" || (policy == "auto" && !cfg.SprayMode))
}

func Execute() {
	cfg := ParseConfig()

	// Read targets from stdin only when NO other target source is supplied
	// (-f file, -H host args) AND stdin is actually piped (not a TTY).
	// Auto-detects naabu/nerva URI/Nerva JSON/fingerprintx JSON/masscan JSON.
	// The HostArgs / File guard prevents CI/test runs where stdin is redirected
	// to /dev/null but the operator passed targets explicitly via -H from
	// triggering an empty-stream error.
	if cfg.File == "" && len(cfg.HostArgs) == 0 && len(cfg.Hosts) == 0 && !term.IsTerminal(int(os.Stdin.Fd())) {
		hosts, err := modules.ParseStream(os.Stdin)
		if err == nil && len(hosts) > 0 {
			cfg.Hosts = append(cfg.Hosts, hosts...)
		}
		// Silently no-op on empty/unrecognized stdin: the operator may have
		// run brutespray with no targets at all (which the existing flow
		// already handles by printing the help banner).
	}

	totalHosts := len(cfg.Hosts)

	configureCircuitBreaker(cfg)
	if err := modules.ConfigureDebugAudit(cfg.DebugAudit, cfg.DebugFile); err != nil {
		fmt.Printf("Error creating debug audit log: %v\n", err)
		os.Exit(1)
	}
	defer modules.CloseDebugAudit()

	// Initialize Connection Manager once
	cm, err := modules.NewConnectionManager(cfg.SocksProxy, cfg.Timeout, cfg.NetInterface)
	if err != nil {
		fmt.Printf("Error creating connection manager: %v\n", err)
		os.Exit(1)
	}

	// Inject --allow-wrapper into module params so the wrapper module can check it
	if cfg.AllowWrapper {
		cfg.ModuleParams["allow-wrapper"] = "true"
	}

	// Set up proxy rotation if proxy list is provided
	if cfg.ProxyList != "" {
		if err := cm.LoadProxyList(cfg.ProxyList); err != nil {
			fmt.Printf("Error loading proxy list: %v\n", err)
			os.Exit(1)
		}
	}

	// Set output format
	modules.OutputFormatMode = cfg.OutputFormat

	if cfg.TUI {
		executeTUI(cfg, cm, totalHosts)
	} else {
		executeLegacy(cfg, cm, totalHosts)
	}
}

// executeTUI runs the interactive Bubble Tea TUI.
func executeTUI(cfg *Config, cm *modules.ConnectionManager, totalHosts int) {
	// Suppress all direct stdout writes — the TUI handles display
	modules.TUIMode = true

	eventBus := tui.NewEventBus()
	modules.ErrorSink = eventBus.SendError
	modules.FindingSink = func(severity, code, service, target, message, cve string) {
		eventBus.Send(tui.FindingMsg{
			Entry: tui.FindingEntry{
				Severity: severity,
				Code:     code,
				Service:  service,
				Target:   target,
				Message:  message,
				CVE:      cve,
				Time:     time.Now(),
			},
		})
	}
	workerPool := NewWorkerPool(cfg.Threads, eventBus, cfg.HostParallelism, totalHosts)
	workerPool.stopOnSuccess = cfg.StopOnSuccess
	workerPool.rateLimit = cfg.RateLimit
	workerPool.sprayMode = cfg.SprayMode
	workerPool.scheduleMode = cfg.ScheduleMode
	workerPool.routeDiagnostics = cfg.RouteDiagnostics
	workerPool.sprayDelay = cfg.SprayDelay
	workerPool.useReversedPass = cfg.UseReversedPass
	workerPool.passwordGen = cfg.PasswordGen
	workerPool.noBadKeys = cfg.NoBadKeys
	workerPool.badKeysOnly = cfg.BadKeysOnly
	workerPool.noRDPScan = cfg.NoRDPScan
	workerPool.inlineCreds = cfg.Creds

	// Initialize checkpoint
	var replayEntries []modules.SessionEntry
	if cfg.ResumeFile != "" {
		cp, err := modules.LoadCheckpoint(cfg.ResumeFile)
		if err != nil {
			fmt.Printf("Error loading checkpoint: %v\n", err)
			os.Exit(1)
		}
		workerPool.checkpoint = cp

		// Load session log for replay
		logPath := modules.SessionLogPath(cfg.ResumeFile)
		entries, err := modules.LoadSessionLog(logPath)
		if err != nil {
			fmt.Printf("Warning: could not load session log: %v\n", err)
		} else {
			replayEntries = entries
		}
	} else {
		workerPool.checkpoint = modules.NewCheckpoint(cfg.CheckpointFile)
	}

	// Initialize session log for recording attempts
	sessionLogPath := modules.SessionLogPath(workerPool.checkpoint.FilePath)
	sessionLog, err := modules.NewSessionLog(sessionLogPath)
	if err != nil {
		fmt.Printf("Warning: could not open session log: %v\n", err)
	} else {
		workerPool.sessionLog = sessionLog
		defer sessionLog.Close()
	}

	checkpointStop := make(chan struct{})
	workerPool.checkpoint.StartPeriodicSave(30*time.Second, checkpointStop)

	// Start worker pool
	workerPool.Start(cfg.Timeout, cfg.Retry, cfg.Output, cm, cfg.Domain, cfg.NoStats)

	// Launch host processing goroutines
	var hostWg sync.WaitGroup
	for _, h := range cfg.Hosts {
		hostWg.Add(1)
		go func(host modules.Host) {
			defer hostWg.Done()
			select {
			case <-workerPool.globalStopChan:
				return
			default:
				workerPool.ProcessHost(host, host.Service, cfg.Combo, cfg.User, cfg.Password, version, cfg.Timeout, cfg.Retry, cfg.Output, cm, cfg.Domain, brute.ModuleParams(cfg.ModuleParams), cfg.UseUsernameAsPass)
			}
		}(h)
	}

	// Signal TUI when all hosts complete
	go func() {
		hostWg.Wait()
		tui.SendDone(eventBus)
	}()

	// Run the TUI (blocks until user exits)
	if err := tui.Run(workerPool, cfg.TotalCombinations, eventBus, version, replayEntries); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}

	// Cleanup
	workerPool.Stop()
	close(checkpointStop)
	if err := workerPool.checkpoint.Save(); err != nil {
		fmt.Printf("[!] Final checkpoint save error: %v\n", err)
	} else {
		fmt.Printf("\n[*] Session saved. Resume with: brutespray -resume %s ...\n", workerPool.checkpoint.FilePath)
	}

	modules.SetTotalHostsAndServices(totalHosts, len(cfg.SupportedServices))
	if cfg.Summary {
		modules.PrintComprehensiveSummary(cfg.Output)
	}
	cm.ClearPool()
	eventBus.Close()
}

// executeLegacy runs the original pterm-based output mode.
func executeLegacy(cfg *Config, cm *modules.ConnectionManager, totalHosts int) {
	totalThreadEstimate := cfg.Threads * totalHosts * 10
	if totalThreadEstimate < 1 {
		totalThreadEstimate = 1
	}
	if totalThreadEstimate > 100000 {
		totalThreadEstimate = 100000
	}
	progressCh := make(chan tui.ProgressEvent, totalThreadEstimate)
	eventSink := tui.NewLegacyEventSink(progressCh)
	workerPool := NewWorkerPool(cfg.Threads, eventSink, cfg.HostParallelism, totalHosts)
	workerPool.stopOnSuccess = cfg.StopOnSuccess
	workerPool.rateLimit = cfg.RateLimit
	workerPool.sprayMode = cfg.SprayMode
	workerPool.scheduleMode = cfg.ScheduleMode
	workerPool.routeDiagnostics = cfg.RouteDiagnostics
	workerPool.sprayDelay = cfg.SprayDelay
	workerPool.useReversedPass = cfg.UseReversedPass
	workerPool.passwordGen = cfg.PasswordGen
	workerPool.noBadKeys = cfg.NoBadKeys
	workerPool.badKeysOnly = cfg.BadKeysOnly
	workerPool.noRDPScan = cfg.NoRDPScan
	workerPool.inlineCreds = cfg.Creds

	// Initialize checkpoint for resume capability
	if cfg.ResumeFile != "" {
		cp, err := modules.LoadCheckpoint(cfg.ResumeFile)
		if err != nil {
			fmt.Printf("Error loading checkpoint: %v\n", err)
			os.Exit(1)
		}
		workerPool.checkpoint = cp
		modules.PrintfColored(pterm.FgLightYellow, "[*] Resuming from checkpoint: %d hosts completed, %d credentials found\n",
			len(cp.CompletedHosts), len(cp.SuccessfulCreds))
	} else {
		workerPool.checkpoint = modules.NewCheckpoint(cfg.CheckpointFile)
	}

	// Initialize session log for recording attempts
	sessionLogPath := modules.SessionLogPath(workerPool.checkpoint.FilePath)
	sessionLog, err := modules.NewSessionLog(sessionLogPath)
	if err != nil {
		fmt.Printf("Warning: could not open session log: %v\n", err)
	} else {
		workerPool.sessionLog = sessionLog
		defer sessionLog.Close()
	}

	// Register signal handler BEFORE launching the goroutine that reads from it
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if cfg.PrintHosts {
		PrintHostTable(cfg.Hosts)
	}

	if cfg.SocksProxy != "" {
		modules.PrintfColored(pterm.FgLightYellow, "Socks5 Proxy: %s\n", cfg.SocksProxy)
	}

	if cfg.NetInterface != "" {
		modules.PrintfColored(pterm.FgLightYellow, "Network Interface: %s\n", cm.Iface)
		ipAddr, err := modules.GetIPv4Address(cm.Iface)
		if err == nil {
			modules.PrintfColored(pterm.FgLightYellow, "Local Address: %s\n", ipAddr)
		}
	}

	modules.PrintlnColored(pterm.FgLightYellow, "\nStarting bruteforce attack...")
	maxConcurrentThreads := cfg.Threads * cfg.HostParallelism
	modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("Threads per Host: %d, Max Concurrent Threads: %d, Concurrent Hosts: %d, Total Combinations: %d", cfg.Threads, maxConcurrentThreads, cfg.HostParallelism, cfg.TotalCombinations))
	modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("Total Hosts: %d, Maximum %d hosts will be processed concurrently", totalHosts, cfg.HostParallelism))

	if NoColorMode {
		fmt.Println("\n[*] Testing credentials...")
	} else {
		spinner, _ := pterm.DefaultSpinner.Start("[*] Testing credentials...")
		time.Sleep(1 * time.Second)
		err := spinner.Stop()
		if err != nil {
			_ = err
		}
	}

	var bar *pterm.ProgressbarPrinter
	if !NoColorMode {
		bar, _ = pterm.DefaultProgressbar.WithTotal(cfg.TotalCombinations).WithTitle("Progress").Start()
	}

	counterMutex, currentCounter, retryCounter := StartProgressTracker(eventSink.ProgressCh(), cfg.TotalCombinations, cfg.Threads, bar)

	// Start periodic checkpoint saves
	checkpointStop := make(chan struct{})
	workerPool.checkpoint.StartPeriodicSave(30*time.Second, checkpointStop)

	// Use sync.Once to prevent the signal handler and main flow from racing on cleanup
	var cleanupOnce sync.Once
	doCleanup := func() {
		cleanupOnce.Do(func() {
			workerPool.Stop()
			close(checkpointStop)

			// Save final checkpoint
			if err := workerPool.checkpoint.Save(); err != nil {
				fmt.Printf("[!] Final checkpoint save error: %v\n", err)
			} else {
				modules.PrintfColored(pterm.FgLightYellow, "[*] Session saved. Resume with: brutespray -resume %s ...\n", workerPool.checkpoint.FilePath)
			}

			if !NoColorMode && bar != nil {
				_, _ = bar.Stop()
			}

			counterMutex.Lock()
			retrySuffix := ""
			if *retryCounter > 0 {
				retrySuffix = fmt.Sprintf(" (%d retry attempts)", *retryCounter)
			}
			modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("[*] Final Status: %d/%d combinations tested%s", *currentCounter, cfg.TotalCombinations, retrySuffix))
			counterMutex.Unlock()

			modules.SetTotalHostsAndServices(totalHosts, len(cfg.SupportedServices))

			if cfg.Summary {
				modules.PrintlnColored(pterm.FgLightYellow, "[*] Generating summary report...")
				modules.PrintComprehensiveSummary(cfg.Output)
			}

			cm.ClearPool()
		})
	}

	go func() {
		<-sigs
		modules.PrintlnColored(pterm.FgLightYellow, "\n[!] Interrupting: Cleaning up and shutting down...")
		doCleanup()
		modules.PrintlnColored(pterm.FgLightYellow, "[*] Cleanup completed. Exiting...")
		os.Exit(0)
	}()

	// Start the worker pool
	workerPool.Start(cfg.Timeout, cfg.Retry, cfg.Output, cm, cfg.Domain, cfg.NoStats)

	// Process hosts with proper parallelism.
	var hostWg sync.WaitGroup
	for _, h := range cfg.Hosts {
		hostWg.Add(1)
		go func(host modules.Host) {
			defer hostWg.Done()
			select {
			case <-workerPool.globalStopChan:
				return
			default:
				workerPool.ProcessHost(host, host.Service, cfg.Combo, cfg.User, cfg.Password, version, cfg.Timeout, cfg.Retry, cfg.Output, cm, cfg.Domain, brute.ModuleParams(cfg.ModuleParams), cfg.UseUsernameAsPass)
			}
		}(h)
	}

	// Wait for all hosts to complete or be interrupted
	done := make(chan struct{})
	go func() {
		hostWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All hosts completed normally
	case <-workerPool.globalStopChan:
		// Interrupted by signal, hosts will stop themselves
		fmt.Println("[*] Waiting for hosts to finish current operations...")
	}

	// Close event sink to stop progress goroutine cleanly
	eventSink.Close()

	// Run cleanup via Once (safe even if signal handler already did it)
	doCleanup()

	// Print performance report (legacy)
	metrics := modules.GetGlobalMetrics()
	metrics.PrintPerformanceReport()

	// Print optimization suggestions
	optimizer := modules.NewPerformanceOptimizer()
	suggestions := optimizer.GetOptimizationSuggestions()
	if !NoColorMode {
		modules.PrintlnColored(pterm.FgLightYellow, "\n=== Performance Optimization Suggestions ===")
		for _, suggestion := range suggestions {
			modules.PrintlnColored(pterm.FgLightCyan, "• "+suggestion)
		}
		modules.PrintlnColored(pterm.FgLightYellow, "===============================================")
	} else {
		fmt.Println("\n=== Performance Optimization Suggestions ===")
		for _, suggestion := range suggestions {
			fmt.Println("• " + suggestion)
		}
		fmt.Println("===============================================")
	}
}
