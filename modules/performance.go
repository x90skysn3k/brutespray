package modules

import (
	"fmt"
	"time"
)

// Deprecated: PerformanceMetrics is superseded by OutputStats. Kept to avoid breaking imports.
// It now proxies to the OutputStats-based implementation.
type PerformanceMetrics struct{}

var metrics = &PerformanceMetrics{}

// RecordAttempt updates only the average response time for the legacy metrics.
// Callers must call modules.RecordAttempt(success) exactly once per attempt to avoid double-counting.
func (pm *PerformanceMetrics) RecordAttempt(success bool, responseTime time.Duration) {
	globalStats.mutex.Lock()
	if globalStats.TotalAttempts == 0 {
		globalStats.AverageResponseTime = responseTime
	} else {
		alpha := 0.1
		globalStats.AverageResponseTime = time.Duration(float64(globalStats.AverageResponseTime)*(1-alpha) + float64(responseTime)*alpha)
	}
	globalStats.mutex.Unlock()
}

// RecordError proxies to the new stats system.
func (pm *PerformanceMetrics) RecordError(isConnectionError bool) { RecordError(isConnectionError) }

// UpdateConcurrency proxies to OutputStats peak concurrency tracking.
func (pm *PerformanceMetrics) UpdateConcurrency(current int) { UpdateConcurrency(current) }

// GetMetrics returns a snapshot emulating the old struct using OutputStatsCopy.
func (pm *PerformanceMetrics) GetMetrics() PerformanceMetrics {
	// No-op: legacy callers use methods like GetAttemptsPerSecond/GetSuccessRate/PrintPerformanceReport.
	return PerformanceMetrics{}
}

func (pm *PerformanceMetrics) GetAttemptsPerSecond() float64 {
	s := GetStats()
	return s.AttemptsPerSecond
}

func (pm *PerformanceMetrics) GetSuccessRate() float64 {
	s := GetStats()
	return s.SuccessRate
}

func (pm *PerformanceMetrics) PrintPerformanceReport() {
	s := CalculateFinalStats()
	fmt.Println("\n=== Performance Report ===")
	fmt.Printf("Total Runtime: %v\n", s.EndTime.Sub(s.StartTime).Round(time.Second))
	fmt.Printf("Total Attempts: %d\n", s.TotalAttempts)
	fmt.Printf("Successful Attempts: %d\n", s.SuccessfulAttempts)
	fmt.Printf("Failed Attempts: %d\n", s.FailedAttempts)
	fmt.Printf("Connection Errors: %d\n", s.ConnectionErrors)
	fmt.Printf("Authentication Errors: %d\n", s.AuthenticationErrors)
	fmt.Printf("Success Rate: %.2f%%\n", s.SuccessRate)
	fmt.Printf("Attempts per Second: %.2f\n", s.AttemptsPerSecond)
	fmt.Printf("Average Response Time: %v\n", s.AverageResponseTime)
	fmt.Printf("Peak Concurrency: %d\n", s.PeakConcurrency)
	fmt.Println("==========================")
}

// GetGlobalMetrics returns the legacy-compatible metrics object.
func GetGlobalMetrics() *PerformanceMetrics { return metrics }

// PerformanceOptimizer now reads from OutputStats.
type PerformanceOptimizer struct{}

func NewPerformanceOptimizer() *PerformanceOptimizer { return &PerformanceOptimizer{} }

func (po *PerformanceOptimizer) GetOptimizationSuggestions() []string {
	s := GetStats()
	suggestions := []string{}

	if s.SuccessRate > 50 {
		suggestions = append(suggestions, "High success rate detected - consider reducing retry attempts to improve speed")
	}
	if s.ConnectionErrors > s.TotalAttempts/10 {
		suggestions = append(suggestions, "High connection error rate - consider increasing timeout or reducing concurrency")
	}
	if s.AverageResponseTime > 5*time.Second {
		suggestions = append(suggestions, "Slow average response time - consider increasing timeout or reducing load")
	}
	if s.PeakConcurrency < 10 {
		suggestions = append(suggestions, "Low concurrency detected - consider increasing thread count")
	}
	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Performance appears optimal with current settings")
	}
	return suggestions
}
