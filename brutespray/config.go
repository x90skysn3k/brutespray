package brutespray

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/banner"
	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"golang.org/x/term"
)

var masterServiceList = brute.Services()

var BetaServiceList = []string{"asterisk", "nntp", "oracle", "xmpp", "rdp", "ldap", "ldaps", "winrm", "ftps", "smtp-vrfy", "rexec", "rlogin", "rsh", "wrapper"}

var version = "dev"
var NoColorMode bool

func init() {
	if version != "dev" {
		return
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
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

// moduleParamsFlag collects multiple -m KEY:VALUE parameters
type moduleParamsFlag []string

func (m *moduleParamsFlag) String() string { return strings.Join(*m, ",") }
func (m *moduleParamsFlag) Set(value string) error {
	if !strings.Contains(value, ":") {
		return fmt.Errorf("module param must be in KEY:VALUE format, got %q", value)
	}
	*m = append(*m, value)
	return nil
}

// Config holds all parsed configuration for a brutespray run
type Config struct {
	User                string
	Password            string
	Combo               string
	Output              string
	Summary             bool
	NoStats             bool
	Silent              bool
	LogEvery            int
	Threads             int
	HostParallelism     int
	SocksProxy          string
	NetInterface        string
	ServiceType         string
	File                string
	HostArgs            hostListFlag
	Quiet               bool
	Timeout             time.Duration
	Retry               int
	PrintHosts          bool
	Domain              string
	NoColor             bool
	StopOnSuccess       bool
	RateLimit           float64
	SprayMode           bool
	SprayDelay          time.Duration
	ResumeFile          string
	CheckpointFile      string
	ConfigFile          string
	TUI                 bool
	Hosts               []modules.Host
	SupportedServices   []string
	TotalCombinations   int
	ModuleParams        map[string]string
	UseUsernameAsPass   bool
}

// ParseConfig parses CLI flags, loads config file, and validates inputs.
// It handles --list-services and usage output, exiting if appropriate.
func ParseConfig() *Config {
	cfg := &Config{}

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
	flag.Var(&cfg.HostArgs, "H", "Target in the format service://host:port, CIDR ranges supported; can be specified multiple times")
	quiet := flag.Bool("q", false, "Suppress the banner")
	timeout := flag.Duration("w", 5*time.Second, "Set timeout delay of bruteforce attempts")
	_ = flag.Bool("insecure", false, "Deprecated: TLS certificate verification is always disabled for bruteforce")
	retry := flag.Int("r", 3, "Amount of times to retry after receiving connection failed")
	printhosts := flag.Bool("P", false, "Print found hosts parsed from provided host and file arguments")
	domain := flag.String("d", "", "Domain to use for RDP authentication (optional)")
	noColor := flag.Bool("nc", false, "Disable colored output")
	stopOnSuccess := flag.Bool("stop-on-success", false, "Stop testing a host after finding valid credentials")
	rateLimit := flag.Float64("rate", 0, "Per-host rate limit in attempts/second (0 = unlimited)")
	sprayMode := flag.Bool("spray", false, "Spray mode: try each password across all users before next password (avoids lockouts)")
	sprayDelay := flag.Duration("spray-delay", 30*time.Minute, "Delay between password rounds in spray mode")
	resumeFile := flag.String("resume", "", "Resume from a checkpoint file (saved automatically on interrupt)")
	checkpointFile := flag.String("checkpoint", "brutespray-checkpoint.json", "Checkpoint file path for resume capability")
	configFile := flag.String("config", "", "YAML config file (CLI flags override config values)")
	noTUI := flag.Bool("no-tui", false, "Disable interactive terminal UI, use legacy output mode")
	var moduleParamsArgs moduleParamsFlag
	flag.Var(&moduleParamsArgs, "m", "Module-specific parameter in KEY:VALUE format (repeatable). Example: -m auth:NTLM -m dir:/admin")
	extraCreds := flag.String("e", "", "Extra password checks: n=blank password, s=password=username, ns=both")

	flag.Parse()

	// Load config file and apply defaults (CLI flags override)
	if *configFile != "" {
		fileCfg, err := modules.LoadConfig(*configFile)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}
		// Track which flags were explicitly set on CLI
		setFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

		// Apply config values only for flags not explicitly set
		if !setFlags["u"] && fileCfg.User != "" {
			*user = fileCfg.User
		}
		if !setFlags["p"] && fileCfg.Password != "" {
			*password = fileCfg.Password
		}
		if !setFlags["C"] && fileCfg.Combo != "" {
			*combo = fileCfg.Combo
		}
		if !setFlags["o"] && fileCfg.Output != "" {
			*output = fileCfg.Output
		}
		if !setFlags["t"] && fileCfg.Threads > 0 {
			*threads = fileCfg.Threads
		}
		if !setFlags["T"] && fileCfg.HostParallelism > 0 {
			*hostParallelism = fileCfg.HostParallelism
		}
		if !setFlags["w"] && fileCfg.Timeout > 0 {
			*timeout = fileCfg.Timeout
		}
		if !setFlags["r"] && fileCfg.Retry > 0 {
			*retry = fileCfg.Retry
		}
		if !setFlags["s"] && fileCfg.Service != "" {
			*serviceType = fileCfg.Service
		}
		if !setFlags["socks5"] && fileCfg.Socks5 != "" {
			*socksProxy = fileCfg.Socks5
		}
		if !setFlags["iface"] && fileCfg.Interface != "" {
			*netInterface = fileCfg.Interface
		}
		if !setFlags["d"] && fileCfg.Domain != "" {
			*domain = fileCfg.Domain
		}
		if !setFlags["rate"] && fileCfg.RateLimit > 0 {
			*rateLimit = fileCfg.RateLimit
		}
		if !setFlags["stop-on-success"] && fileCfg.StopOnSuccess {
			*stopOnSuccess = true
		}
		if !setFlags["silent"] && fileCfg.Silent {
			*silent = true
		}
		if !setFlags["log-every"] && fileCfg.LogEvery > 0 {
			*logEvery = fileCfg.LogEvery
		}
		if !setFlags["summary"] && fileCfg.Summary {
			*summary = true
		}
		if !setFlags["nc"] && fileCfg.NoColor {
			*noColor = true
		}
		if !setFlags["spray"] && fileCfg.Spray {
			*sprayMode = true
		}
		if !setFlags["spray-delay"] && fileCfg.SprayDelay > 0 {
			*sprayDelay = fileCfg.SprayDelay
		}
		if !setFlags["f"] && fileCfg.File != "" {
			*file = fileCfg.File
		}
		// Load module params from config if not set via CLI
		if len(moduleParamsArgs) == 0 && len(fileCfg.ModuleParams) > 0 {
			for k, v := range fileCfg.ModuleParams {
				moduleParamsArgs = append(moduleParamsArgs, k+":"+v)
			}
		}
		if !setFlags["e"] && fileCfg.ExtraCreds != "" {
			*extraCreds = fileCfg.ExtraCreds
		}
		if len(fileCfg.Hosts) > 0 && len(cfg.HostArgs) == 0 {
			for _, h := range fileCfg.Hosts {
				cfg.HostArgs = append(cfg.HostArgs, h)
			}
		}
	}

	// Assign parsed values to config
	cfg.User = *user
	cfg.Password = *password
	cfg.Combo = *combo
	cfg.Output = *output
	cfg.Summary = *summary
	cfg.NoStats = *noStats
	cfg.Silent = *silent
	cfg.LogEvery = *logEvery
	cfg.Threads = *threads
	cfg.HostParallelism = *hostParallelism
	cfg.SocksProxy = *socksProxy
	cfg.NetInterface = *netInterface
	cfg.ServiceType = *serviceType
	cfg.File = *file
	cfg.Quiet = *quiet
	cfg.Timeout = *timeout
	cfg.Retry = *retry
	cfg.PrintHosts = *printhosts
	cfg.Domain = *domain
	cfg.NoColor = *noColor
	cfg.StopOnSuccess = *stopOnSuccess
	cfg.RateLimit = *rateLimit
	cfg.SprayMode = *sprayMode
	cfg.SprayDelay = *sprayDelay
	// If user passed the .jsonl session log, resolve to the .json checkpoint
	resume := *resumeFile
	if strings.HasSuffix(resume, ".jsonl") {
		resume = strings.TrimSuffix(resume, ".jsonl") + ".json"
	}
	cfg.ResumeFile = resume
	cfg.CheckpointFile = *checkpointFile
	cfg.ConfigFile = *configFile
	// TUI is default for interactive terminals; --no-tui or --nc disables it
	cfg.TUI = !*noTUI && !cfg.NoColor && term.IsTerminal(int(os.Stdout.Fd()))

	// Parse module parameters from -m flags
	cfg.ModuleParams = make(map[string]string)
	for _, mp := range moduleParamsArgs {
		parts := strings.SplitN(mp, ":", 2)
		cfg.ModuleParams[parts[0]] = parts[1]
	}

	// Parse -e flag for extra credential checks
	if *extraCreds != "" {
		e := strings.ToLower(*extraCreds)
		if strings.Contains(e, "s") {
			cfg.UseUsernameAsPass = true
		}
		if strings.Contains(e, "n") {
			modules.UseEmptyPassword = true
		}
	}

	// Apply global settings
	NoColorMode = cfg.NoColor
	modules.NoColorMode = cfg.NoColor
	modules.Silent = cfg.Silent
	if cfg.LogEvery < 1 {
		cfg.LogEvery = 1
	}
	modules.LogEvery = int64(cfg.LogEvery)

	// If -p was provided explicitly and is empty (length zero), instruct
	// modules to use a single blank password instead of default wordlist.
	{
		providedPassword := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "p" {
				providedPassword = true
			}
		})
		if providedPassword && cfg.Password == "" {
			modules.UseEmptyPassword = true
		}
	}

	banner.Banner(version, cfg.Quiet, NoColorMode)

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
			fmt.Println("Supported services:", strings.Join(getSupportedServices(cfg.ServiceType), ", "))
		} else {
			pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(cfg.ServiceType), ", "))
		}
		os.Exit(0)
	} else {
		if flag.NFlag() == 0 {
			flag.Usage()
			if NoColorMode {
				fmt.Println("Supported services:", strings.Join(getSupportedServices(cfg.ServiceType), ", "))
			} else {
				pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(cfg.ServiceType), ", "))
			}
			os.Exit(2)
		}
	}

	if len(cfg.HostArgs) == 0 && cfg.File == "" {
		flag.Usage()
		os.Exit(2)
	}

	// Parse hosts from file
	var hosts map[modules.Host]int
	if cfg.File != "" {
		if !modules.IsFile(cfg.File) {
			fmt.Fprintln(os.Stderr, "Invalid -f path: file does not exist or is not accessible:", cfg.File)
			os.Exit(2)
		}
		var err error
		hosts, err = modules.ParseFile(cfg.File)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse input file:", err)
			os.Exit(1)
		}
	}

	for h := range hosts {
		cfg.Hosts = append(cfg.Hosts, h)
	}

	// Parse all -H hosts
	if len(cfg.HostArgs) > 0 {
		var hostObj modules.Host
		for _, hostArg := range cfg.HostArgs {
			parsed, err := hostObj.Parse(hostArg)
			if err != nil {
				fmt.Println("Error parsing host:", err)
				os.Exit(1)
			}
			cfg.Hosts = append(cfg.Hosts, parsed...)
		}
	}

	cfg.SupportedServices = getSupportedServices(cfg.ServiceType)

	// Calculate total combinations
	for _, service := range cfg.SupportedServices {
		for _, h := range cfg.Hosts {
			if h.Service == service {
				for _, beta := range BetaServiceList {
					if beta == h.Service {
						modules.PrintWarningBeta(h.Service)
					}
				}
				if cfg.Combo != "" {
					users, passwords := modules.GetUsersAndPasswordsCombo(&h, cfg.Combo, version)
					cfg.TotalCombinations += modules.CalcCombinationsCombo(users, passwords)
				} else {
					if service == "vnc" || service == "snmp" {
						_, passwords, err := modules.GetUsersAndPasswords(&h, cfg.User, cfg.Password, version)
						if err != nil {
							fmt.Printf("Error loading wordlist for %s: %v\n", service, err)
							continue
						}
						cfg.TotalCombinations += modules.CalcCombinationsPass(passwords)
					} else {
						users, passwords, err := modules.GetUsersAndPasswords(&h, cfg.User, cfg.Password, version)
						if err != nil {
							fmt.Printf("Error loading wordlist for %s: %v\n", service, err)
							continue
						}
						cfg.TotalCombinations += modules.CalcCombinations(users, passwords)
					}
				}
			}
		}
	}

	// Validate threads per host (no upper limit)
	if cfg.Threads < 1 {
		cfg.Threads = 1
	}

	// Optimize host parallelism
	totalHosts := len(cfg.Hosts)
	if cfg.HostParallelism > totalHosts {
		cfg.HostParallelism = totalHosts
	}
	if cfg.HostParallelism < 1 {
		cfg.HostParallelism = 1
	}

	return cfg
}
