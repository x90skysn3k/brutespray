package modules

import (
	"fmt"
	"sync"
	"time"
)

// PerformanceMetrics tracks various performance metrics
type PerformanceMetrics struct {
	StartTime            time.Time
	TotalAttempts        int64
	SuccessfulAttempts   int64
	FailedAttempts       int64
	ConnectionErrors     int64
	AuthenticationErrors int64
	AverageResponseTime  time.Duration
	PeakConcurrency      int
	CurrentConcurrency   int
	mutex                sync.RWMutex
}

var metrics = &PerformanceMetrics{
	StartTime: time.Now(),
}

// RecordAttempt records a brute force attempt
func (pm *PerformanceMetrics) RecordAttempt(success bool, responseTime time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.TotalAttempts++

	if success {
		pm.SuccessfulAttempts++
	} else {
		pm.FailedAttempts++
	}

	// Update average response time
	if pm.TotalAttempts == 1 {
		pm.AverageResponseTime = responseTime
	} else {
		// Exponential moving average
		alpha := 0.1
		pm.AverageResponseTime = time.Duration(float64(pm.AverageResponseTime)*(1-alpha) + float64(responseTime)*alpha)
	}
}

// RecordError records a connection or authentication error
func (pm *PerformanceMetrics) RecordError(isConnectionError bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if isConnectionError {
		pm.ConnectionErrors++
	} else {
		pm.AuthenticationErrors++
	}
}

// UpdateConcurrency updates the current concurrency level
func (pm *PerformanceMetrics) UpdateConcurrency(current int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.CurrentConcurrency = current
	if current > pm.PeakConcurrency {
		pm.PeakConcurrency = current
	}
}

// GetMetrics returns a copy of current metrics
func (pm *PerformanceMetrics) GetMetrics() PerformanceMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return PerformanceMetrics{
		StartTime:            pm.StartTime,
		TotalAttempts:        pm.TotalAttempts,
		SuccessfulAttempts:   pm.SuccessfulAttempts,
		FailedAttempts:       pm.FailedAttempts,
		ConnectionErrors:     pm.ConnectionErrors,
		AuthenticationErrors: pm.AuthenticationErrors,
		AverageResponseTime:  pm.AverageResponseTime,
		PeakConcurrency:      pm.PeakConcurrency,
		CurrentConcurrency:   pm.CurrentConcurrency,
	}
}

// GetAttemptsPerSecond calculates attempts per second
func (pm *PerformanceMetrics) GetAttemptsPerSecond() float64 {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	duration := time.Since(pm.StartTime).Seconds()
	if duration == 0 {
		return 0
	}

	return float64(pm.TotalAttempts) / duration
}

// GetSuccessRate calculates the success rate
func (pm *PerformanceMetrics) GetSuccessRate() float64 {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if pm.TotalAttempts == 0 {
		return 0
	}

	return float64(pm.SuccessfulAttempts) / float64(pm.TotalAttempts) * 100
}

// PrintPerformanceReport prints a comprehensive performance report
func (pm *PerformanceMetrics) PrintPerformanceReport() {
	metrics := pm.GetMetrics()

	fmt.Println("\n=== Performance Report ===")
	fmt.Printf("Total Runtime: %v\n", time.Since(metrics.StartTime).Round(time.Second))
	fmt.Printf("Total Attempts: %d\n", metrics.TotalAttempts)
	fmt.Printf("Successful Attempts: %d\n", metrics.SuccessfulAttempts)
	fmt.Printf("Failed Attempts: %d\n", metrics.FailedAttempts)
	fmt.Printf("Connection Errors: %d\n", metrics.ConnectionErrors)
	fmt.Printf("Authentication Errors: %d\n", metrics.AuthenticationErrors)
	fmt.Printf("Success Rate: %.2f%%\n", pm.GetSuccessRate())
	fmt.Printf("Attempts per Second: %.2f\n", pm.GetAttemptsPerSecond())
	fmt.Printf("Average Response Time: %v\n", metrics.AverageResponseTime)
	fmt.Printf("Peak Concurrency: %d\n", metrics.PeakConcurrency)
	fmt.Println("==========================")
}

// GetGlobalMetrics returns the global metrics instance
func GetGlobalMetrics() *PerformanceMetrics {
	return metrics
}

// PerformanceOptimizer provides performance optimization suggestions
type PerformanceOptimizer struct {
	metrics *PerformanceMetrics
}

func NewPerformanceOptimizer() *PerformanceOptimizer {
	return &PerformanceOptimizer{
		metrics: GetGlobalMetrics(),
	}
}

// GetOptimizationSuggestions returns performance optimization suggestions
func (po *PerformanceOptimizer) GetOptimizationSuggestions() []string {
	metrics := po.metrics.GetMetrics()
	suggestions := []string{}

	// Analyze success rate
	successRate := po.metrics.GetSuccessRate()
	if successRate > 50 {
		suggestions = append(suggestions, "High success rate detected - consider reducing retry attempts to improve speed")
	}

	// Analyze connection errors
	if metrics.ConnectionErrors > metrics.TotalAttempts/10 {
		suggestions = append(suggestions, "High connection error rate - consider increasing timeout or reducing concurrency")
	}

	// Analyze response times
	if metrics.AverageResponseTime > 5*time.Second {
		suggestions = append(suggestions, "Slow average response time - consider increasing timeout or reducing load")
	}

	// Analyze concurrency
	if metrics.PeakConcurrency < 10 {
		suggestions = append(suggestions, "Low concurrency detected - consider increasing thread count")
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Performance appears optimal with current settings")
	}

	return suggestions
}
