package brutespray

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/brute"
	"github.com/x90skysn3k/brutespray/modules"
)

func Execute() {
	cfg := ParseConfig()

	totalHosts := len(cfg.Hosts)

	// Create optimized worker pool with per-host thread allocation
	totalThreadEstimate := cfg.Threads * totalHosts * 10
	if totalThreadEstimate < 1 {
		totalThreadEstimate = 1
	}
	if totalThreadEstimate > 100000 {
		totalThreadEstimate = 100000
	}
	progressCh := make(chan int, totalThreadEstimate)
	workerPool := NewWorkerPool(cfg.Threads, progressCh, cfg.HostParallelism, totalHosts)
	workerPool.stopOnSuccess = cfg.StopOnSuccess
	workerPool.rateLimit = cfg.RateLimit
	workerPool.sprayMode = cfg.SprayMode
	workerPool.sprayDelay = cfg.SprayDelay

	// Only enable the circuit breaker in spray mode where skipping unreachable
	// hosts is useful. In normal mode, keep trying — connection hiccups are common.
	brute.GetCircuitBreaker().SetDisabled(!cfg.SprayMode)

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

	// Register signal handler BEFORE launching the goroutine that reads from it
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if cfg.PrintHosts {
		PrintHostTable(cfg.Hosts)
	}

	if cfg.SocksProxy != "" {
		modules.PrintfColored(pterm.FgLightYellow, "Socks5 Proxy: %s\n", cfg.SocksProxy)
	}

	// Initialize Connection Manager once
	cm, err := modules.NewConnectionManager(cfg.SocksProxy, cfg.Timeout, cfg.NetInterface)
	if err != nil {
		fmt.Printf("Error creating connection manager: %v\n", err)
		os.Exit(1)
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
		err = spinner.Stop()
		if err != nil {
			_ = err
		}
	}

	var bar *pterm.ProgressbarPrinter
	if !NoColorMode {
		bar, _ = pterm.DefaultProgressbar.WithTotal(cfg.TotalCombinations).WithTitle("Progress").Start()
	}

	counterMutex, currentCounter := StartProgressTracker(progressCh, cfg.TotalCombinations, cfg.Threads, bar)

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
				modules.PrintfColored(pterm.FgLightYellow, "[*] Checkpoint saved to %s\n", workerPool.checkpoint.FilePath)
			}

			if !NoColorMode && bar != nil {
				_, _ = bar.Stop()
			}

			counterMutex.Lock()
			modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("[*] Final Status: %d/%d combinations tested", *currentCounter, cfg.TotalCombinations))
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
	// Interleave dispatch across services so that a large SSH list doesn't
	// starve FTP/HTTP targets waiting behind the host semaphore.
	var hostWg sync.WaitGroup
	for _, h := range cfg.Hosts {
		hostWg.Add(1)
		go func(host modules.Host) {
			defer hostWg.Done()
			select {
			case <-workerPool.globalStopChan:
				return
			default:
				workerPool.ProcessHost(host, host.Service, cfg.Combo, cfg.User, cfg.Password, version, cfg.Timeout, cfg.Retry, cfg.Output, cm, cfg.Domain)
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

	// Close progress channel to stop progress goroutine cleanly
	close(progressCh)

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
