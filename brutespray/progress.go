package brutespray

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/modules"
)

// PrintHostTable prints the discovered hosts and services table
func PrintHostTable(hostsList []modules.Host) {
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

// StartProgressTracker starts a goroutine that reads from progressCh and updates
// the progress bar (or prints text progress in NoColor mode).
// Returns a mutex and counter for use during cleanup.
func StartProgressTracker(progressCh <-chan int, totalCombinations int, threads int, bar *pterm.ProgressbarPrinter) (*sync.Mutex, *int) {
	counterMutex := &sync.Mutex{}
	currentCounter := new(int)

	go func() {
		for range progressCh {
			counterMutex.Lock()
			*currentCounter++
			modules.OutputMu.Lock()
			if NoColorMode {
				// Update progress periodically. Avoid modulo by zero when threads is small.
				step := threads / 2
				if step < 1 {
					step = 1
				}
				if *currentCounter%step == 0 || *currentCounter == totalCombinations {
					fmt.Printf("\n[*] Progress: %d/%d combinations tested\n", *currentCounter, totalCombinations)
				}
			} else {
				bar.Increment()
			}
			modules.OutputMu.Unlock()
			counterMutex.Unlock()
		}
	}()

	return counterMutex, currentCounter
}
