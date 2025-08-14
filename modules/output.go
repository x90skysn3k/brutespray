package modules

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sync/atomic"

	"github.com/pterm/pterm"
)

// NoColorMode controls whether colored output is disabled
var NoColorMode bool

// Silent controls whether to suppress per-attempt logs (successes still printed)
var Silent bool

// LogEvery controls attempt logging frequency; 1 = log every attempt
var LogEvery int64 = 1
var attemptCounter int64

// SuccessResult represents a successful credential attempt
type SuccessResult struct {
	Service  string    `json:"service"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	User     string    `json:"user"`
	Password string    `json:"password"`
	Time     time.Time `json:"time"`
	Duration string    `json:"duration"`
}

// OutputStats tracks comprehensive statistics for the bruteforce session
type OutputStats struct {
	StartTime            time.Time       `json:"start_time"`
	EndTime              time.Time       `json:"end_time"`
	TotalAttempts        int64           `json:"total_attempts"`
	SuccessfulAttempts   int64           `json:"successful_attempts"`
	FailedAttempts       int64           `json:"failed_attempts"`
	ConnectionErrors     int64           `json:"connection_errors"`
	AuthenticationErrors int64           `json:"authentication_errors"`
	SuccessRate          float64         `json:"success_rate"`
	AttemptsPerSecond    float64         `json:"attempts_per_second"`
	AverageResponseTime  time.Duration   `json:"average_response_time"`
	PeakConcurrency      int             `json:"peak_concurrency"`
	TotalHosts           int             `json:"total_hosts"`
	TotalServices        int             `json:"total_services"`
	SuccessfulResults    []SuccessResult `json:"successful_results"`
	ServiceBreakdown     map[string]int  `json:"service_breakdown"`
	HostBreakdown        map[string]int  `json:"host_breakdown"`
	ConnectionErrorHosts map[string]int  `json:"connection_error_hosts"`
	mutex                sync.RWMutex
}

// OutputStatsCopy is a copy of OutputStats without the mutex for safe copying
type OutputStatsCopy struct {
	StartTime            time.Time       `json:"start_time"`
	EndTime              time.Time       `json:"end_time"`
	TotalAttempts        int64           `json:"total_attempts"`
	SuccessfulAttempts   int64           `json:"successful_attempts"`
	FailedAttempts       int64           `json:"failed_attempts"`
	ConnectionErrors     int64           `json:"connection_errors"`
	AuthenticationErrors int64           `json:"authentication_errors"`
	SuccessRate          float64         `json:"success_rate"`
	AttemptsPerSecond    float64         `json:"attempts_per_second"`
	AverageResponseTime  time.Duration   `json:"average_response_time"`
	PeakConcurrency      int             `json:"peak_concurrency"`
	TotalHosts           int             `json:"total_hosts"`
	TotalServices        int             `json:"total_services"`
	SuccessfulResults    []SuccessResult `json:"successful_results"`
	ServiceBreakdown     map[string]int  `json:"service_breakdown"`
	HostBreakdown        map[string]int  `json:"host_breakdown"`
	ConnectionErrorHosts map[string]int  `json:"connection_error_hosts"`
}

var globalStats = &OutputStats{
	StartTime:            time.Now(),
	SuccessfulResults:    make([]SuccessResult, 0),
	ServiceBreakdown:     make(map[string]int),
	HostBreakdown:        make(map[string]int),
	ConnectionErrorHosts: make(map[string]int),
}

// PrintlnColored prints a colored message with newline
func PrintlnColored(color pterm.Color, msg string) {
	if NoColorMode {
		fmt.Println(msg)
	} else {
		pterm.Println(pterm.NewStyle(color).Sprint(msg))
	}
}

// PrintfColored prints a formatted colored message
func PrintfColored(color pterm.Color, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if NoColorMode {
		fmt.Print(msg)
	} else {
		pterm.Print(pterm.NewStyle(color).Sprint(msg))
	}
}

func getConResultString(con_result bool, retrying bool, delayTime time.Duration) string {
	var delaying bool
	if delayTime > 2*time.Second {
		delaying = true
	}
	if !retrying {
		return "connection failed, giving up..."
	} else if retrying && delaying {
		return fmt.Sprintf("connection failed, retrying... delayed %s", delayTime)
	} else {
		return "connection failed, retrying..."
	}
}

// WriteToFile writes success results to individual service files (legacy format)
func WriteToFile(service string, content string, port int, output string) error {
	var dir string
	if output != "brutespray-output" {
		dir = output
	} else {
		dir = output
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	filename := filepath.Join(dir, fmt.Sprintf("%d-%s-success.txt", port, service))
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}

// RecordSuccess records a successful credential attempt
func RecordSuccess(service string, host string, port int, user string, password string, duration time.Duration) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	result := SuccessResult{
		Service:  service,
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		Time:     time.Now(),
		Duration: duration.String(),
	}

	globalStats.SuccessfulResults = append(globalStats.SuccessfulResults, result)
	globalStats.SuccessfulAttempts++
	globalStats.ServiceBreakdown[service]++
	globalStats.HostBreakdown[host]++
}

// RecordAttempt records any attempt (success or failure)
func RecordAttempt(success bool) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	globalStats.TotalAttempts++
	if !success {
		globalStats.FailedAttempts++
	}
}

// RecordError records connection or authentication errors
func RecordError(isConnectionError bool) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	if isConnectionError {
		globalStats.ConnectionErrors++
	} else {
		globalStats.AuthenticationErrors++
	}
}

// RecordConnectionError records a connection error for a specific host
func RecordConnectionError(host string) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	globalStats.ConnectionErrors++
	globalStats.ConnectionErrorHosts[host]++
}

// UpdateConcurrency updates concurrency metrics
func UpdateConcurrency(current int) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	if current > globalStats.PeakConcurrency {
		globalStats.PeakConcurrency = current
	}
}

// SetTotalHostsAndServices sets the total counts for hosts and services
func SetTotalHostsAndServices(hosts int, services int) {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	globalStats.TotalHosts = hosts
	globalStats.TotalServices = services
}

// GetStats returns a copy of current statistics
func GetStats() OutputStatsCopy {
	globalStats.mutex.RLock()
	defer globalStats.mutex.RUnlock()

	// Create a new struct without the mutex to avoid copy locks
	stats := OutputStatsCopy{
		StartTime:            globalStats.StartTime,
		EndTime:              globalStats.EndTime,
		TotalAttempts:        globalStats.TotalAttempts,
		SuccessfulAttempts:   globalStats.SuccessfulAttempts,
		FailedAttempts:       globalStats.FailedAttempts,
		ConnectionErrors:     globalStats.ConnectionErrors,
		AuthenticationErrors: globalStats.AuthenticationErrors,
		SuccessRate:          globalStats.SuccessRate,
		AttemptsPerSecond:    globalStats.AttemptsPerSecond,
		AverageResponseTime:  globalStats.AverageResponseTime,
		PeakConcurrency:      globalStats.PeakConcurrency,
		TotalHosts:           globalStats.TotalHosts,
		TotalServices:        globalStats.TotalServices,
	}

	// Copy slices and maps
	stats.SuccessfulResults = make([]SuccessResult, len(globalStats.SuccessfulResults))
	copy(stats.SuccessfulResults, globalStats.SuccessfulResults)

	stats.ServiceBreakdown = make(map[string]int)
	for k, v := range globalStats.ServiceBreakdown {
		stats.ServiceBreakdown[k] = v
	}

	stats.HostBreakdown = make(map[string]int)
	for k, v := range globalStats.HostBreakdown {
		stats.HostBreakdown[k] = v
	}

	stats.ConnectionErrorHosts = make(map[string]int)
	for k, v := range globalStats.ConnectionErrorHosts {
		stats.ConnectionErrorHosts[k] = v
	}

	return stats
}

// CalculateFinalStats calculates final statistics
func CalculateFinalStats() OutputStatsCopy {
	stats := GetStats()
	stats.EndTime = time.Now()

	if stats.TotalAttempts > 0 {
		stats.SuccessRate = float64(stats.SuccessfulAttempts) / float64(stats.TotalAttempts) * 100
	}

	duration := stats.EndTime.Sub(stats.StartTime).Seconds()
	if duration > 0 {
		stats.AttemptsPerSecond = float64(stats.TotalAttempts) / duration
	}

	return stats
}

// PrintResult prints individual results (legacy format for compatibility)
func PrintResult(service string, host string, port int, user string, pass string, result bool, con_result bool, progressCh chan<- int, retrying bool, output string, delayTime time.Duration) {
	// Always write successes to file, but gate console noise via Silent/LogEvery
	var msg string
	var color pterm.Color

	if result && con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, "SUCCESS")
			color = pterm.BgGreen
			content := fmt.Sprintf("[%s] %s:%d - Password '%s' - %s\n", service, host, port, pass, "SUCCESS")
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, "SUCCESS")
			color = pterm.BgGreen
			content := fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s\n", service, host, port, user, pass, "SUCCESS")
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		}
	} else if !result && con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, "FAILED")
			color = pterm.FgLightRed
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, "FAILED")
			color = pterm.FgLightRed
		}
	} else if !result && !con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, getConResultString(con_result, retrying, delayTime))
			color = pterm.FgRed
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, getConResultString(con_result, retrying, delayTime))
			color = pterm.FgRed
		}
	}
	// Determine if we should print this attempt
	shouldPrint := true
	if Silent && !(result && con_result) {
		shouldPrint = false
	}
	if !Silent && !(result && con_result) && LogEvery > 1 {
		n := atomic.AddInt64(&attemptCounter, 1)
		if n%LogEvery != 0 {
			shouldPrint = false
		}
	}
	if shouldPrint {
		pterm.Println(pterm.NewStyle(color).Sprint(msg))
	}
}

// PrintWarningBeta prints beta service warnings
func PrintWarningBeta(service string) {
	pterm.Println(pterm.NewStyle(pterm.BgYellow).Sprint(fmt.Sprintf("[!] Warning: %s module is in Beta - results may be inaccurate", service)))
}

// PrintSocksError prints SOCKS proxy errors
func PrintSocksError(service string, err string) {
	// Keep message but ensure it is concise
	pterm.Println(pterm.NewStyle(pterm.FgRed).Sprint(fmt.Sprintf("[!] %s: SOCKS5 connection failed - %s", service, err)))
}

// PrintSkipping prints host skipping messages
func PrintSkipping(host string, service string, retries int, maxRetries int) {
	pterm.Println(pterm.NewStyle(pterm.FgRed).Sprint(fmt.Sprintf("[!] Warning: Skipping %s on %s - max retries (%d/%d) reached", service, host, retries, maxRetries)))
}

// PrintComprehensiveSummary prints a comprehensive summary report
func PrintComprehensiveSummary(outputDir string) {
	stats := CalculateFinalStats()

	// Create output directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.Mkdir(outputDir, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			return
		}
	}

	// Print to console
	printSummaryToConsole(&stats)

	// Write JSON report
	writeJSONReport(&stats, outputDir)

	// Write CSV report
	writeCSVReport(&stats, outputDir)

	// Write human-readable summary
	writeHumanReadableSummary(&stats, outputDir)
}

// printSummaryToConsole prints the summary to console
func printSummaryToConsole(stats *OutputStatsCopy) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                    BRUTESPRAY SUMMARY REPORT")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Session Duration: %v\n", stats.EndTime.Sub(stats.StartTime).Round(time.Second))
	fmt.Printf("Start Time: %s\n", stats.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("End Time: %s\n", stats.EndTime.Format("2006-01-02 15:04:05"))

	fmt.Println("\n--- ATTEMPT STATISTICS ---")
	fmt.Printf("Total Attempts: %d\n", stats.TotalAttempts)
	fmt.Printf("Successful Attempts: %d\n", stats.SuccessfulAttempts)
	fmt.Printf("Failed Attempts: %d\n", stats.FailedAttempts)
	fmt.Printf("Success Rate: %.2f%%\n", stats.SuccessRate)
	fmt.Printf("Attempts per Second: %.2f\n", stats.AttemptsPerSecond)

	fmt.Println("\n--- ERROR STATISTICS ---")
	fmt.Printf("Connection Errors: %d\n", stats.ConnectionErrors)
	fmt.Printf("Authentication Errors: %d\n", stats.AuthenticationErrors)

	if len(stats.ConnectionErrorHosts) > 0 {
		fmt.Println("\n--- CONNECTION ERROR HOSTS ---")
		for host, count := range stats.ConnectionErrorHosts {
			fmt.Printf("%s: %d connection errors\n", host, count)
		}
	}

	fmt.Println("\n--- PERFORMANCE STATISTICS ---")
	fmt.Printf("Average Response Time: %v\n", stats.AverageResponseTime)
	fmt.Printf("Peak Concurrency: %d\n", stats.PeakConcurrency)

	fmt.Println("\n--- SCOPE STATISTICS ---")
	fmt.Printf("Total Hosts: %d\n", stats.TotalHosts)
	fmt.Printf("Total Services: %d\n", stats.TotalServices)

	if len(stats.SuccessfulResults) > 0 {
		fmt.Println("\n--- SUCCESSFUL CREDENTIALS ---")
		for i, result := range stats.SuccessfulResults {
			if i >= 10 { // Limit to first 10 for console
				fmt.Printf("... and %d more successful attempts\n", len(stats.SuccessfulResults)-10)
				break
			}
			if result.Service == "vnc" {
				fmt.Printf("[%s] %s:%d - Password: %s\n", result.Service, result.Host, result.Port, result.Password)
			} else {
				fmt.Printf("[%s] %s:%d - User: %s - Password: %s\n", result.Service, result.Host, result.Port, result.User, result.Password)
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

// writeJSONReport writes a JSON report
func writeJSONReport(stats *OutputStatsCopy, outputDir string) {
	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON report: %v\n", err)
		return
	}

	filename := filepath.Join(outputDir, "brutespray-summary.json")
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON report: %v\n", err)
		return
	}

	fmt.Printf("JSON report written to: %s\n", filename)
}

// writeCSVReport writes a CSV report
func writeCSVReport(stats *OutputStatsCopy, outputDir string) {
	filename := filepath.Join(outputDir, "brutespray-summary.csv")
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating CSV report: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write summary statistics
	summaryData := [][]string{
		{"Metric", "Value"},
		{"Start Time", stats.StartTime.Format("2006-01-02 15:04:05")},
		{"End Time", stats.EndTime.Format("2006-01-02 15:04:05")},
		{"Duration", stats.EndTime.Sub(stats.StartTime).String()},
		{"Total Attempts", fmt.Sprintf("%d", stats.TotalAttempts)},
		{"Successful Attempts", fmt.Sprintf("%d", stats.SuccessfulAttempts)},
		{"Failed Attempts", fmt.Sprintf("%d", stats.FailedAttempts)},
		{"Success Rate", fmt.Sprintf("%.2f%%", stats.SuccessRate)},
		{"Attempts per Second", fmt.Sprintf("%.2f", stats.AttemptsPerSecond)},
		{"Connection Errors", fmt.Sprintf("%d", stats.ConnectionErrors)},
		{"Authentication Errors", fmt.Sprintf("%d", stats.AuthenticationErrors)},
		{"Peak Concurrency", fmt.Sprintf("%d", stats.PeakConcurrency)},
		{"Total Hosts", fmt.Sprintf("%d", stats.TotalHosts)},
		{"Total Services", fmt.Sprintf("%d", stats.TotalServices)},
	}

	if err := writer.WriteAll(summaryData); err != nil {
		fmt.Printf("Error writing CSV data: %v\n", err)
		return
	}

	// Write connection error hosts if any
	if len(stats.ConnectionErrorHosts) > 0 {
		if err := writer.Write([]string{}); err != nil { // Empty line
			fmt.Printf("Error writing CSV data: %v\n", err)
			return
		}
		if err := writer.Write([]string{"Connection Error Hosts"}); err != nil {
			fmt.Printf("Error writing CSV data: %v\n", err)
			return
		}
		if err := writer.Write([]string{"Host", "Error Count"}); err != nil {
			fmt.Printf("Error writing CSV data: %v\n", err)
			return
		}

		for host, count := range stats.ConnectionErrorHosts {
			if err := writer.Write([]string{host, fmt.Sprintf("%d", count)}); err != nil {
				fmt.Printf("Error writing CSV data: %v\n", err)
				return
			}
		}
	}

	// Write successful results
	if len(stats.SuccessfulResults) > 0 {
		if err := writer.Write([]string{}); err != nil { // Empty line
			fmt.Printf("Error writing CSV data: %v\n", err)
			return
		}
		if err := writer.Write([]string{"Service", "Host", "Port", "User", "Password", "Time", "Duration"}); err != nil {
			fmt.Printf("Error writing CSV data: %v\n", err)
			return
		}

		for _, result := range stats.SuccessfulResults {
			if err := writer.Write([]string{
				result.Service,
				result.Host,
				fmt.Sprintf("%d", result.Port),
				result.User,
				result.Password,
				result.Time.Format("2006-01-02 15:04:05"),
				result.Duration,
			}); err != nil {
				fmt.Printf("Error writing CSV data: %v\n", err)
				return
			}
		}
	}

	fmt.Printf("CSV report written to: %s\n", filename)
}

// writeHumanReadableSummary writes a human-readable summary
func writeHumanReadableSummary(stats *OutputStatsCopy, outputDir string) {
	filename := filepath.Join(outputDir, "brutespray-summary.txt")
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating summary file: %v\n", err)
		return
	}
	defer file.Close()

	// Write the same content as console but to file
	fmt.Fprintf(file, "%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(file, "                    BRUTESPRAY SUMMARY REPORT\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("=", 60))

	fmt.Fprintf(file, "Session Duration: %v\n", stats.EndTime.Sub(stats.StartTime).Round(time.Second))
	fmt.Fprintf(file, "Start Time: %s\n", stats.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "End Time: %s\n", stats.EndTime.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(file, "\n--- ATTEMPT STATISTICS ---\n")
	fmt.Fprintf(file, "Total Attempts: %d\n", stats.TotalAttempts)
	fmt.Fprintf(file, "Successful Attempts: %d\n", stats.SuccessfulAttempts)
	fmt.Fprintf(file, "Failed Attempts: %d\n", stats.FailedAttempts)
	fmt.Fprintf(file, "Success Rate: %.2f%%\n", stats.SuccessRate)
	fmt.Fprintf(file, "Attempts per Second: %.2f\n", stats.AttemptsPerSecond)

	fmt.Fprintf(file, "\n--- ERROR STATISTICS ---\n")
	fmt.Fprintf(file, "Connection Errors: %d\n", stats.ConnectionErrors)
	fmt.Fprintf(file, "Authentication Errors: %d\n", stats.AuthenticationErrors)

	if len(stats.ConnectionErrorHosts) > 0 {
		fmt.Fprintf(file, "\n--- CONNECTION ERROR HOSTS ---\n")
		for host, count := range stats.ConnectionErrorHosts {
			fmt.Fprintf(file, "%s: %d connection errors\n", host, count)
		}
	}

	fmt.Fprintf(file, "\n--- PERFORMANCE STATISTICS ---\n")
	fmt.Fprintf(file, "Average Response Time: %v\n", stats.AverageResponseTime)
	fmt.Fprintf(file, "Peak Concurrency: %d\n", stats.PeakConcurrency)

	fmt.Fprintf(file, "\n--- SCOPE STATISTICS ---\n")
	fmt.Fprintf(file, "Total Hosts: %d\n", stats.TotalHosts)
	fmt.Fprintf(file, "Total Services: %d\n", stats.TotalServices)

	if len(stats.SuccessfulResults) > 0 {
		fmt.Fprintf(file, "\n--- SUCCESSFUL CREDENTIALS ---\n")
		for _, result := range stats.SuccessfulResults {
			if result.Service == "vnc" {
				fmt.Fprintf(file, "[%s] %s:%d - Password: %s\n", result.Service, result.Host, result.Port, result.Password)
			} else {
				fmt.Fprintf(file, "[%s] %s:%d - User: %s - Password: %s\n", result.Service, result.Host, result.Port, result.User, result.Password)
			}
		}
	}

	fmt.Fprintf(file, "%s\n", strings.Repeat("=", 60))

	fmt.Printf("Human-readable summary written to: %s\n", filename)
}
