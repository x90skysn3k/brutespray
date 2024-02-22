package brutespray

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/banner"
	"github.com/x90skysn3k/brutespray/brute"
	"github.com/x90skysn3k/brutespray/modules"
)

var masterServiceList = []string{"ssh", "ftp", "smtp", "mssql", "telnet", "smbnt", "postgres", "imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc"}

var alphaServiceList = []string{"asterisk"}

var version = "v2.1.4"

func Execute() {
	user := flag.String("u", "", "Username or user list to bruteforce")
	password := flag.String("p", "", "Password or password file to use for bruteforce")
	threads := flag.Int("t", 10, "Number of threads to use")
	serviceType := flag.String("s", "all", "Service type: ssh, ftp, smtp, etc; Default all")
	listServices := flag.Bool("S", false, "List all supported services")
	file := flag.String("f", "", "File to parse; Supported: Nmap, Nessus, Nexpose, Lists, etc")
	host := flag.String("H", "", "Target in the format service://host:port, CIDR ranges supported,\n default port will be used if not specified")
	quiet := flag.Bool("q", false, "Supress the banner")
	timeout := flag.Duration("T", 5*time.Second, "Set timeout of bruteforce attempts")
	retry := flag.Int("r", 3, "Ammount of times to retry after recieving connection failed")

	flag.Parse()

	banner.Banner(version, *quiet)

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
		pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
		os.Exit(1)
	} else {
		if flag.NFlag() == 0 {
			flag.Usage()
			pterm.DefaultSection.Println("Supported services:", strings.Join(getSupportedServices(*serviceType), ", "))
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
				users, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
				totalCombinations += modules.CalcCombinations(users, passwords)
				if service == "vnc" || service == "snmp" {
					_, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
					totalCombinations += modules.CalcCombinationsPass(passwords)
				}
			}
		}
	}

	bar, _ := pterm.DefaultProgressbar.WithTotal(len(hostsList)*(totalCombinations) - nopassServices).WithTitle("Bruteforcing...").Start()
	var wg sync.WaitGroup
	var bruteForceWg sync.WaitGroup
	sem := make(chan struct{}, *threads)
	sigs := make(chan os.Signal, 1)
	progressCh := make(chan int, totalCombinations)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		pterm.DefaultSection.Println("\nReceived an interrupt signal, shutting down...")
		time.Sleep(5 * time.Second)
		bar.Stop()
		os.Exit(0)
	}()

	go func() {
		for range progressCh {
			bar.Increment()
		}
	}()

	for _, service := range supportedServices {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()
			if service == "vnc" || service == "snmp" {
				u := ""
				for _, h := range hostsList {
					if h.Service == service {
						_, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
						stopChan := make(chan struct{})
						for _, p := range passwords {
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
									brute.RunBrute(h, u, p, progressCh, *timeout, *retry)
									bruteForceWg.Add(1)
								}
								progressCh <- 1
							}(h, p)
						}
					}
				}
			} else {
				for _, h := range hostsList {
					if h.Service == service {
						for _, alpha := range alphaServiceList {
							if alpha == h.Service {
								modules.PrintWarningAlpha(h.Service)
							}
						}
						users, passwords := modules.GetUsersAndPasswords(&h, *user, *password, version)
						stopChan := make(chan struct{})
						for _, u := range users {
							for _, p := range passwords {
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
										brute.RunBrute(h, u, p, progressCh, *timeout, *retry)
										bruteForceWg.Add(1)
									}
									progressCh <- 1
								}(h, u, p)
							}
						}
					}
				}
			}
		}(service)
	}

	wg.Wait()
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
	bruteForceWg.Wait()
	bar.Stop()
}
