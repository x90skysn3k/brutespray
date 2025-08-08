package brutespray

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/banner"
	"github.com/x90skysn3k/brutespray/brute"
	"github.com/x90skysn3k/brutespray/modules"
)

var masterServiceList = []string{"ssh", "ftp", "smtp", "mssql", "telnet", "smbnt", "postgres", "imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc", "mongodb", "nntp", "oracle", "teamspeak", "xmpp", "rdp"}

var BetaServiceList = []string{"asterisk", "nntp", "oracle", "xmpp", "rdp"}

var version = "v2.3.2"
var NoColorMode bool

func Execute() {
	user := flag.String("u", "", "Username or user list to bruteforce For SMBNT and RDP, use domain\\username format (e.g., CORP\\jdoe)")
	password := flag.String("p", "", "Password or password file to use for bruteforce")
	combo := flag.String("C", "", "Specify a combo wordlist deiminated by ':', example: user1:password")
	output := flag.String("o", "brutespray-output", "Directory containing successful attempts")
	threads := flag.Int("t", 10, "Number of threads to use")
	hostParallelism := flag.Int("T", 5, "Number of hosts to bruteforce at the same time")
	socksProxy := flag.String("socks5", "", "Socks5 proxy to use for bruteforce")
	netInterface := flag.String("iface", "", "Specific network interface to use for bruteforce traffic")
	serviceType := flag.String("s", "all", "Service type: ssh, ftp, smtp, etc; Default all")
	listServices := flag.Bool("S", false, "List all supported services")
	file := flag.String("f", "", "File to parse; Supported: Nmap, Nessus, Nexpose, Lists, etc")
	host := flag.String("H", "", "Target in the format service://host:port, CIDR ranges supported,\n default port will be used if not specified")
	quiet := flag.Bool("q", false, "Suppress the banner")
	timeout := flag.Duration("w", 5*time.Second, "Set timeout delay of bruteforce attempts")
	retry := flag.Int("r", 3, "Amount of times to retry after receiving connection failed")
	printhosts := flag.Bool("P", false, "Print found hosts parsed from provided host and file arguments")
	domain := flag.String("d", "", "Domain to use for RDP authentication (optional)")
	noColor := flag.Bool("nc", false, "Disable colored output")

	flag.Parse()

	NoColorMode = *noColor
	modules.NoColorMode = *noColor
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
		os.Exit(1)
	} else {
		if flag.NFlag() == 0 {
			flag.Usage()
			if NoColorMode {
				fmt.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
			} else {
				pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
			}
			os.Exit(1)
		}
	}

	if *host == "" && *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	hosts, err := modules.ParseFile(*file)
	if err != nil && *file != "" {
		fmt.Println("Error parsing file:", err)
		os.Exit(1)
	}

	var hostsList []modules.Host
	for h := range hosts {
		hostsList = append(hostsList, h)
	}

	if *host != "" {
		var hostObj modules.Host
		host, err := hostObj.Parse(*host)
		if err != nil {
			fmt.Println("Error parsing host:", err)
			os.Exit(1)
		}
		hostsList = append(hostsList, host...)
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
	var wg sync.WaitGroup
	var bruteForceWg sync.WaitGroup
	sem := make(chan struct{}, *threads**hostParallelism)
	hostSem := make(chan struct{}, *hostParallelism)
	sigs := make(chan os.Signal, 1)
	progressCh := make(chan int, totalCombinations)

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

	modules.PrintlnColored(pterm.FgLightYellow, "\nStarting to brute, please make sure to use the right amount of threads(-t) and parallel hosts(-T)...")

	if NoColorMode {
		fmt.Println("Starting Bruteforce...")
		time.Sleep(3 * time.Second)
	} else {
		spinner, _ := pterm.DefaultSpinner.Start("Starting Bruteforce...")
		time.Sleep(3 * time.Second)
		err = spinner.Stop()
		if err != nil {
			_ = err
		}
	}

	var bar *pterm.ProgressbarPrinter
	if NoColorMode {
		fmt.Printf("Bruteforcing... (0/%d)\n", (totalCombinations)-nopassServices)
	} else {
		bar, _ = pterm.DefaultProgressbar.WithTotal((totalCombinations) - nopassServices).WithTitle("Bruteforcing...").Start()
	}

	go func() {
		counter := 0
		for range progressCh {
			counter++
			if NoColorMode {
				fmt.Printf("\rBruteforcing... (%d/%d)\n", counter, (totalCombinations)-nopassServices)
			} else {
				bar.Increment()
			}
		}
	}()

	go func() {
		<-sigs
		modules.PrintlnColored(pterm.FgLightYellow, "\nReceived an interrupt signal, shutting down...")
		time.Sleep(5 * time.Second)
		if !NoColorMode {
			_, _ = bar.Stop()
		}
		brute.ClearMaps()
		os.Exit(0)
	}()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	totalHosts := len(hostsList)

	if *hostParallelism > totalHosts {
		*hostParallelism = totalHosts
	}

	if *threads > *retry {
		*threads = *retry
	}

	for _, service := range supportedServices {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()
			if service == "vnc" || service == "snmp" {
				u := ""
				if *combo != "" {
					for _, h := range hostsList {
						h := h
						if h.Service == service {
							_, passwords := modules.GetUsersAndPasswordsCombo(&h, *combo, version)
							stopChan := make(chan struct{})
							hostSem <- struct{}{}

							go func() {
								defer func() { <-hostSem }()
								for _, p := range passwords {
									p := p
									wg.Add(1)
									sem <- struct{}{}

									go func(h modules.Host, p string) {
										defer func() {
											<-sem
											wg.Done()
											bruteForceWg.Done()
										}()

										select {
										case <-stopChan:
										default:
											brute.RunBrute(h, u, p, progressCh, *timeout, *retry, *output, *socksProxy, *netInterface, *domain)
											bruteForceWg.Add(1)
										}
										progressCh <- 1
									}(h, p)
								}
							}()
						}
					}
				} else {
					for _, h := range hostsList {
						h := h
						if h.Service == service {
							_, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
							stopChan := make(chan struct{})
							hostSem <- struct{}{}

							go func() {
								defer func() { <-hostSem }()
								for _, p := range passwords {
									p := p
									wg.Add(1)
									sem <- struct{}{}

									go func(h modules.Host, p string) {
										defer func() {
											<-sem
											wg.Done()
											bruteForceWg.Done()
										}()

										select {
										case <-stopChan:
										default:
											brute.RunBrute(h, u, p, progressCh, *timeout, *retry, *output, *socksProxy, *netInterface, *domain)
											bruteForceWg.Add(1)
										}
										progressCh <- 1
									}(h, p)
								}
							}()
						}
					}
				}
			} else {
				if *combo != "" {
					for _, h := range hostsList {
						h := h
						if h.Service == service {
							users, passwords := modules.GetUsersAndPasswordsCombo(&h, *combo, version)
							stopChan := make(chan struct{})
							hostSem <- struct{}{}

							go func() {
								defer func() { <-hostSem }()
								for i := range users {
									u := users[i]
									p := passwords[i]
									wg.Add(1)
									sem <- struct{}{}

									go func(h modules.Host, u, p string) {
										defer func() {
											<-sem
											wg.Done()
											bruteForceWg.Done()
										}()

										select {
										case <-stopChan:
											return
										default:
											brute.RunBrute(h, u, p, progressCh, *timeout, *retry, *output, *socksProxy, *netInterface, *domain)
											bruteForceWg.Add(1)
										}
										progressCh <- 1
									}(h, u, p)
								}
							}()
						}
					}
				} else {
					for _, h := range hostsList {
						h := h
						if h.Service == service {
							users, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
							stopChan := make(chan struct{})
							hostSem <- struct{}{}

							go func() {
								defer func() { <-hostSem }()
								for _, u := range users {
									u := u
									for _, p := range passwords {
										p := p
										wg.Add(1)
										sem <- struct{}{}

										go func(h modules.Host, u, p string) {
											defer func() {
												<-sem
												wg.Done()
												bruteForceWg.Done()
											}()

											select {
											case <-stopChan:
												return
											default:
												brute.RunBrute(h, u, p, progressCh, *timeout, *retry, *output, *socksProxy, *netInterface, *domain)
												bruteForceWg.Add(1)
											}
											progressCh <- 1
										}(h, u, p)
									}
								}
							}()
						}
					}
				}
			}
		}(service)
	}
	wg.Wait()
	for i := 0; i < cap(hostSem); i++ {
		hostSem <- struct{}{}
	}
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
	bruteForceWg.Wait()
	if !NoColorMode {
		_, _ = bar.Stop()
	}
	defer brute.ClearMaps()
}
