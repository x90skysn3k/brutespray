package tui

import (
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
)

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
	Status    string
	Timestamp time.Time
	Banner    string
	KeyMatch  *brute.KeyMatch // non-nil when the attempt matched a known-bad SSH key
}

// ProgressEvent tells legacy progress rendering whether an attempt consumed a
// base credential combination or was an extra retry of a previously missed
// credential.
type ProgressEvent struct {
	Retry bool
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

// FindingEntry holds a single pre-auth recon finding.
type FindingEntry struct {
	Severity string
	Code     string
	Service  string
	Target   string
	Message  string
	CVE      string
	Time     time.Time
}

// FindingMsg is sent when a pre-auth recon finding is produced.
type FindingMsg struct {
	Entry FindingEntry
}
