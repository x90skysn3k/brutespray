package tui

import "time"

// AttemptResultMsg is sent by workers after each credential attempt.
type AttemptResultMsg struct {
	Host      string
	Port      int
	Service   string
	User      string
	Password  string
	Success   bool
	Connected bool
	Error     error
	Duration  time.Duration
	Retrying  bool
	Timestamp time.Time
	Banner    string
}

// HostStartedMsg is sent when a host begins processing.
type HostStartedMsg struct {
	Host    string
	Port    int
	Service string
	Threads int
}

// HostCompletedMsg is sent when a host finishes all attempts.
type HostCompletedMsg struct {
	Host          string
	Port          int
	Service       string
	TotalAttempts int64
	SuccessRate   float64
	AvgResponseMs float64
}

// BatchAttemptMsg carries multiple attempt results for high-throughput batching.
type BatchAttemptMsg []AttemptResultMsg

// ErrorMsg carries an error message to display in the TUI.
type ErrorMsg struct {
	Message   string
	Timestamp time.Time
}
