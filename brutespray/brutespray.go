package brutespray

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/banner"
	"github.com/x90skysn3k/brutespray/brute"
	"github.com/x90skysn3k/brutespray/modules"
)

var masterServiceList = []string{"ssh", "ftp", "smtp", "mssql", "telnet", "smbnt", "postgres", "imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc", "mongodb", "nntp", "oracle", "teamspeak", "xmpp", "rdp", "http", "https"}

var BetaServiceList = []string{"asterisk", "nntp", "oracle", "xmpp", "rdp"}

var version = "v2.4.1"
var NoColorMode bool

// Credential represents a single credential attempt
type Credential struct {
	Host     modules.Host
	User     string
	Password string
	Service  string
}

// hostListFlag collects multiple -H targets
type hostListFlag []string

func (h *hostListFlag) String() string { return strings.Join(*h, ",") }
func (h *hostListFlag) Set(value string) error {
	if value == "" {
		return fmt.Errorf("empty host provided to -H")
	}
	*h = append(*h, value)
	return nil
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
}

// NewHostWorkerPool creates a new host-specific worker pool
func NewHostWorkerPool(host modules.Host, workers int, progressCh chan int) *HostWorkerPool {
	return &HostWorkerPool{
		host:          host,
		workers:       workers,
		targetWorkers: workers,
		jobQueue:      make(chan Credential, workers*10), // Smaller buffer per host
		progressCh:    progressCh,
		stopChan:      make(chan struct{}),
	}
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
		maxThreadsPerHost: threadsPerHost,
		scalerStop:        make(chan struct{}),
	}
}

// Start starts the host-specific worker pool
func (hwp *HostWorkerPool) Start(timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string, noStats bool) {
	for i := 0; i < hwp.workers; i++ {
		hwp.wg.Add(1)
		atomic.AddInt32(&hwp.currentWorkers, 1)
		go hwp.worker(timeout, retry, output, socksProxy, netInterface, domain, noStats)
	}
}

// scaleTo adjusts the number of workers towards target. It can only add workers; reducing
// happens cooperatively when workers finish a job and see they are above target.
func (hwp *HostWorkerPool) scaleTo(newTarget int, timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string, noStats bool) {
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
		go hwp.worker(timeout, retry, output, socksProxy, netInterface, domain, noStats)
	}
}

// Start starts all host worker pools
func (wp *WorkerPool) Start(timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string, noStats bool) {
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
					hp.scaleTo(target, timeout, retry, output, socksProxy, netInterface, domain, noStats)
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
func (hwp *HostWorkerPool) worker(timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string, noStats bool) {
	defer hwp.wg.Done()

	for {
		// If scaling down and queue appears empty, allow this worker to exit
		if int(atomic.LoadInt32(&hwp.currentWorkers)) > hwp.targetWorkers {
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
					hwp.processCredential(cred, timeout, retry, output, socksProxy, netInterface, domain, noStats)
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
			hwp.processCredential(cred, timeout, retry, output, socksProxy, netInterface, domain, noStats)
		}
	}
}

func (hwp *HostWorkerPool) processCredential(cred Credential, timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string, noStats bool) {
	// Track performance for dynamic adjustment
	startTime := time.Now()

	// Execute the brute force attempt
	success := brute.RunBrute(cred.Host, cred.User, cred.Password, hwp.progressCh, timeout, retry, output, socksProxy, netInterface, domain)

	// Record statistics (if enabled)
	duration := time.Since(startTime)
	if !noStats {
		if !success {
			modules.RecordConnectionError(cred.Host.Host)
		}
	}

	// Update performance metrics
	hwp.updatePerformanceMetrics(success, duration)
	hwp.progressCh <- 1
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

			hostPool = NewHostWorkerPool(host, threadsForHost, wp.progressCh)
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

// Helper function for min

// ProcessHost processes a single host with all its credentials using dedicated host worker pool
func (wp *WorkerPool) ProcessHost(host modules.Host, service string, combo string, user string, password string, version string, timeout time.Duration, retry int, output string, socksProxy string, netInterface string, domain string) {
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
	hostPool.Start(timeout, retry, output, socksProxy, netInterface, domain, wp.noStats)

	// Debug output to show host processing
	if !NoColorMode {
		modules.PrintfColored(pterm.FgLightGreen, "[*] Processing host: %s:%d (%s) with %d threads\n", host.Host, host.Port, host.Service, hostPool.workers)
	} else {
		fmt.Printf("[*] Processing host: %s:%d (%s) with %d threads\n", host.Host, host.Port, host.Service, hostPool.workers)
	}

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
			_, passwords := modules.GetUsersAndPasswords(&host, user, password, version)
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
			users, passwords := modules.GetUsersAndPasswords(&host, user, password, version)
			for _, u := range users {
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
						User:     u,
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

	if !NoColorMode {
		modules.PrintfColored(pterm.FgLightGreen, "[*] Completed host: %s:%d (%s) - %d attempts, %.1f%% success, avg %.2fs\n",
			host.Host, host.Port, host.Service, totalAttempts, successRate*100, avgResponseTime.Seconds())
	} else {
		fmt.Printf("[*] Completed host: %s:%d (%s) - %d attempts, %.1f%% success, avg %.2fs\n",
			host.Host, host.Port, host.Service, totalAttempts, successRate*100, avgResponseTime.Seconds())
	}
}

func Execute() {
	user := flag.String("u", "", "Username or user list to bruteforce For SMBNT and RDP, use domain\\username format (e.g., CORP\\jdoe)")
	password := flag.String("p", "", "Password or password file to use for bruteforce")
	combo := flag.String("C", "", "Specify a combo wordlist deiminated by ':', example: user1:password")
	output := flag.String("o", "brutespray-output", "Directory containing successful attempts")
	summary := flag.Bool("summary", false, "Generate comprehensive summary report with statistics")
	noStats := flag.Bool("no-stats", false, "Disable statistics tracking for better performance")
	silent := flag.Bool("silent", false, "Suppress per-attempt console logs (still records successes and summary)")
	logEvery := flag.Int("log-every", 1, "Print every N attempts when not in silent mode (>=1)")
	threads := flag.Int("t", 10, "Number of threads per host (also acts as max threads per host)")
	hostParallelism := flag.Int("T", 5, "Number of hosts to bruteforce at the same time")
	socksProxy := flag.String("socks5", "", "Socks5 proxy to use for bruteforce (supports socks5://user:pass@host:port or host:port)")
	netInterface := flag.String("iface", "", "Specific network interface to use for bruteforce traffic (defaults to active interface)")
	serviceType := flag.String("s", "all", "Service type: ssh, ftp, smtp, etc; Default all")
	listServices := flag.Bool("S", false, "List all supported services")
	file := flag.String("f", "", "File to parse; Supported: Nmap, Nessus, Nexpose, Lists, etc")
	var hostArgs hostListFlag
	flag.Var(&hostArgs, "H", "Target in the format service://host:port, CIDR ranges supported; can be specified multiple times")
	quiet := flag.Bool("q", false, "Suppress the banner")
	timeout := flag.Duration("w", 5*time.Second, "Set timeout delay of bruteforce attempts")
	insecureTLS := flag.Bool("insecure", false, "Disable TLS certificate verification for HTTPS bruteforce")
	retry := flag.Int("r", 3, "Amount of times to retry after receiving connection failed")
	printhosts := flag.Bool("P", false, "Print found hosts parsed from provided host and file arguments")
	domain := flag.String("d", "", "Domain to use for RDP authentication (optional)")
	noColor := flag.Bool("nc", false, "Disable colored output")

	flag.Parse()

	NoColorMode = *noColor
	modules.NoColorMode = *noColor
	modules.InsecureTLS = *insecureTLS
	modules.Silent = *silent
	if *logEvery < 1 {
		*logEvery = 1
	}
	modules.LogEvery = int64(*logEvery)
	// If -p was provided explicitly and is empty (length zero), instruct
	// modules to use a single blank password instead of default wordlist.
	// We detect this by checking the presence of -p in the provided args.
	{
		providedEmptyPass := false
		for _, arg := range os.Args[1:] {
			if arg == "-p" || strings.HasPrefix(arg, "-p=") || arg == "--p" || strings.HasPrefix(arg, "--p=") {
				providedEmptyPass = true
				break
			}
		}
		if providedEmptyPass && *password == "" {
			modules.UseEmptyPassword = true
		}
	}
	banner.Banner(version, *quiet, NoColorMode)

	getSupportedServices := func(serviceType string) []string {
		if serviceType != "all" {
			supportedServices := strings.Split(serviceType, ",")
			for i := range supportedServices {
				supportedServices[i] = strings.TrimSpace(supportedServices[i])
			}
			return supportedServices
		}
		return masterServiceList
	}

	if *listServices {
		if NoColorMode {
			fmt.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
		} else {
			pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
		}
		os.Exit(0)
	} else {
		if flag.NFlag() == 0 {
			flag.Usage()
			if NoColorMode {
				fmt.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
			} else {
				pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
			}
			os.Exit(2)
		}
	}

	if len(hostArgs) == 0 && *file == "" {
		flag.Usage()
		os.Exit(2)
	}

	var hosts map[modules.Host]int
	var err error
	if *file != "" {
		// Pre-validate the provided file path and emit a standardized error on stderr
		if !modules.IsFile(*file) {
			fmt.Fprintln(os.Stderr, "Invalid -f path: file does not exist or is not accessible:", *file)
			os.Exit(2)
		}
		hosts, err = modules.ParseFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse input file:", err)
			os.Exit(1)
		}
	}

	var hostsList []modules.Host
	for h := range hosts {
		hostsList = append(hostsList, h)
	}

	// Parse all -H hosts
	if len(hostArgs) > 0 {
		var hostObj modules.Host
		for _, hostArg := range hostArgs {
			parsed, err := hostObj.Parse(hostArg)
			if err != nil {
				fmt.Println("Error parsing host:", err)
				os.Exit(1)
			}
			hostsList = append(hostsList, parsed...)
		}
	}

	supportedServices := getSupportedServices(*serviceType)

	totalCombinations := 0
	nopassServices := 0
	for _, service := range supportedServices {
		for _, h := range hostsList {
			if h.Service == service {
				for _, beta := range BetaServiceList {
					if beta == h.Service {
						modules.PrintWarningBeta(h.Service)
					}
				}
				if *combo != "" {
					users, passwords := modules.GetUsersAndPasswordsCombo(&h, *combo, version)
					totalCombinations += modules.CalcCombinationsCombo(users, passwords)
				} else {
					if service == "vnc" || service == "snmp" {
						_, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
						totalCombinations += modules.CalcCombinationsPass(passwords)
					} else {
						users, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
						totalCombinations += modules.CalcCombinations(users, passwords)
					}
				}
			}
		}
	}

	// Validate threads per host (no upper limit)
	if *threads < 1 {
		*threads = 1
	}

	// Optimize host parallelism
	totalHosts := len(hostsList)
	if *hostParallelism > totalHosts {
		*hostParallelism = totalHosts
	}
	if *hostParallelism < 1 {
		*hostParallelism = 1
	}

	// Create optimized worker pool with per-host thread allocation
	// Buffer based on total threads across all hosts but cap to prevent huge memory spikes
	totalThreadEstimate := (*threads) * totalHosts * 10
	if totalThreadEstimate < 1 {
		totalThreadEstimate = 1
	}
	if totalThreadEstimate > 100000 {
		totalThreadEstimate = 100000
	}
	progressCh := make(chan int, totalThreadEstimate)
	workerPool := NewWorkerPool(*threads, progressCh, *hostParallelism, totalHosts)

	sigs := make(chan os.Signal, 1)

	if *printhosts {
		modules.PrintlnColored(pterm.FgLightGreen, "Found Services:")
		data := pterm.TableData{}

		header := []string{"IP", "Service and Port"}
		data = append(data, header)

		hostToServices := make(map[string][]string)

		for _, h := range hostsList {
			portstr := strconv.Itoa(h.Port)
			service := h.Service + " on port " + portstr
			if _, ok := hostToServices[h.Host]; !ok {
				hostToServices[h.Host] = []string{service}
			} else {
				hostToServices[h.Host] = append(hostToServices[h.Host], service)
			}
		}

		for ip, services := range hostToServices {
			row := []string{ip, strings.Join(services, "\n")}
			data = append(data, row)
		}

		if NoColorMode {
			// Print table data in plain text format
			fmt.Println("Found Services:")
			for i, row := range data {
				if i == 0 {
					fmt.Println("IP\tService and Port")
					fmt.Println("--\t----------------")
				} else {
					fmt.Printf("%s\t%s\n", row[0], row[1])
				}
			}
		} else {
			err := pterm.DefaultTable.WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
			if err != nil {
				_ = err
			}
		}
		if NoColorMode {
			fmt.Println("Waiting...")
			time.Sleep(3 * time.Second)
		} else {
			spinner, _ := pterm.DefaultSpinner.Start("Waiting...")
			time.Sleep(3 * time.Second)
			err := spinner.Stop()
			if err != nil {
				_ = err
			}
		}
	}

	if *netInterface != "" {
		ifaceName, err := modules.ValidateNetworkInterface(*netInterface)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		ipAddr, err := modules.GetIPv4Address(ifaceName)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		modules.PrintfColored(pterm.FgLightYellow, "Network Interface: %s\n", *netInterface)
		modules.PrintfColored(pterm.FgLightYellow, "Local Address: %s\n", ipAddr)
	}

	if *socksProxy != "" {
		modules.PrintfColored(pterm.FgLightYellow, "Socks5 Proxy: %s\n", *socksProxy)
	}

	modules.PrintlnColored(pterm.FgLightYellow, "\nStarting bruteforce attack...")
	modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("Threads per Host: %d, Total Threads: %d, Concurrent Hosts: %d, Total Combinations: %d", *threads, workerPool.globalWorkers, *hostParallelism, (totalCombinations)-nopassServices))
	modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("Total Hosts: %d, Maximum %d hosts will be processed concurrently", totalHosts, *hostParallelism))

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
		bar, _ = pterm.DefaultProgressbar.WithTotal((totalCombinations) - nopassServices).WithTitle("Progress").Start()
	}

	currentCounter := 0
	counterMutex := sync.Mutex{}

	go func() {
		for range progressCh {
			counterMutex.Lock()
			currentCounter++
			if NoColorMode {
				// Update progress periodically. Avoid modulo by zero when threads is small.
				step := (*threads) / 2
				if step < 1 {
					step = 1
				}
				if currentCounter%step == 0 || currentCounter == (totalCombinations)-nopassServices {
					fmt.Printf("\n[*] Progress: %d/%d combinations tested\n", currentCounter, (totalCombinations)-nopassServices)
				}
			} else {
				bar.Increment()
			}
			counterMutex.Unlock()
		}
	}()

	go func() {
		<-sigs
		modules.PrintlnColored(pterm.FgLightYellow, "\n[!] Interrupting: Cleaning up and shutting down...")

		// Immediately stop all worker pools
		workerPool.Stop()

		// Stop progress bar if running
		if !NoColorMode && bar != nil {
			_, _ = bar.Stop()
		}

		// Print final status
		counterMutex.Lock()
		modules.PrintlnColored(pterm.FgLightYellow, fmt.Sprintf("[*] Final Status: %d/%d combinations tested", currentCounter, (totalCombinations)-nopassServices))
		counterMutex.Unlock()

		// Set total hosts and services for statistics (if not already set)
		modules.SetTotalHostsAndServices(totalHosts, len(supportedServices))

		// Print comprehensive summary report if requested (even on interrupt)
		if *summary {
			modules.PrintlnColored(pterm.FgLightYellow, "[*] Generating summary report...")
			modules.PrintComprehensiveSummary(*output)
		}

		// Clean up and exit immediately
		brute.ClearMaps()
		modules.PrintlnColored(pterm.FgLightYellow, "[*] Cleanup completed. Exiting...")
		os.Exit(0)
	}()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Start the worker pool
	workerPool.Start(*timeout, *retry, *output, *socksProxy, *netInterface, *domain, *noStats)

	// Process hosts with proper parallelism
	var hostWg sync.WaitGroup
	for _, service := range supportedServices {
		for _, h := range hostsList {
			if h.Service == service {
				hostWg.Add(1)
				// Process each host in its own goroutine with host parallelism control
				go func(host modules.Host, svc string) {
					defer hostWg.Done()
					// Check if we should stop before processing
					select {
					case <-workerPool.globalStopChan:
						return
					default:
						workerPool.ProcessHost(host, svc, *combo, *user, *password, version, *timeout, *retry, *output, *socksProxy, *netInterface, *domain)
					}
				}(h, service)
			}
		}
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
		// Give a brief moment for graceful shutdown, then force exit will happen in signal handler
	}

	// Close progress channel to stop progress goroutine cleanly
	close(progressCh)

	// Stop the worker pool after all work is done
	workerPool.Stop()

	if !NoColorMode {
		_, _ = bar.Stop()
	}

	// Set total hosts and services for statistics
	modules.SetTotalHostsAndServices(totalHosts, len(supportedServices))

	// Print comprehensive summary report if requested
	if *summary {
		modules.PrintComprehensiveSummary(*output)
	}

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

	defer brute.ClearMaps()
}
