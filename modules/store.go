package modules

import "time"

// Store records engagement runs, targets, attempts, and findings.
type Store interface {
	CreateRun(StoreRun) (string, error)
	RecordTarget(runID string, target StoreTarget) error
	RecordAttempt(runID string, attempt StoreAttempt) error
	RecordFinding(runID string, finding StoreFinding) error
	LoadRun(runID string) (StoreSnapshot, error)
	Close() error
}

// StoreRun identifies an execution run.
type StoreRun struct {
	ID           string    `json:"id"`
	EngagementID string    `json:"engagement_id,omitempty"`
	PlanHash     string    `json:"plan_hash,omitempty"`
	StartedAt    time.Time `json:"started_at"`
}

// StoreTarget records an in-scope target.
type StoreTarget struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

// StoreAttempt records an attempted credential without requiring plaintext secrets.
type StoreAttempt struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user,omitempty"`
	Success bool   `json:"success"`
	Status  string `json:"status,omitempty"`
}

// StoreFinding records a pre-auth or post-auth finding.
type StoreFinding struct {
	Service    string `json:"service"`
	Target     string `json:"target"`
	Code       string `json:"code"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	ProofType  string `json:"proof_type,omitempty"`
}

// StoreSnapshot is a complete run loaded from a store.
type StoreSnapshot struct {
	Run      StoreRun       `json:"run"`
	Targets  []StoreTarget  `json:"targets"`
	Attempts []StoreAttempt `json:"attempts"`
	Findings []StoreFinding `json:"findings"`
}
