package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Checkpoint tracks progress for resume capability.
type Checkpoint struct {
	mu              sync.Mutex
	FilePath        string
	CompletedHosts  map[string]bool `json:"completed_hosts"`  // "host:port:service" -> true
	AttemptedCreds  map[string]int  `json:"attempted_creds"`  // "host:port:service" -> count of creds tried
	SuccessfulCreds []SuccessEntry  `json:"successful_creds"` // creds found so far
	StartTime       time.Time       `json:"start_time"`
	LastSave        time.Time       `json:"last_save"`
}

// SuccessEntry records a found credential in the checkpoint.
type SuccessEntry struct {
	Service  string `json:"service"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// NewCheckpoint creates a new checkpoint tracker.
func NewCheckpoint(filePath string) *Checkpoint {
	return &Checkpoint{
		FilePath:       filePath,
		CompletedHosts: make(map[string]bool),
		AttemptedCreds: make(map[string]int),
		StartTime:      time.Now(),
	}
}

// LoadCheckpoint loads a checkpoint from a JSON file.
func LoadCheckpoint(filePath string) (*Checkpoint, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint: %w", err)
	}

	cp := &Checkpoint{
		FilePath: filePath,
	}
	if err := json.Unmarshal(data, cp); err != nil {
		return nil, fmt.Errorf("parsing checkpoint: %w", err)
	}

	// Re-initialize maps if nil (shouldn't happen but defensive)
	if cp.CompletedHosts == nil {
		cp.CompletedHosts = make(map[string]bool)
	}
	if cp.AttemptedCreds == nil {
		cp.AttemptedCreds = make(map[string]int)
	}

	return cp, nil
}

func hostKey(host string, port int, service string) string {
	return fmt.Sprintf("%s:%d:%s", host, port, service)
}

// IsHostCompleted returns true if the host was fully tested in a previous run.
func (cp *Checkpoint) IsHostCompleted(host string, port int, service string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.CompletedHosts[hostKey(host, port, service)]
}

// MarkHostCompleted marks a host as fully tested.
func (cp *Checkpoint) MarkHostCompleted(host string, port int, service string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.CompletedHosts[hostKey(host, port, service)] = true
}

// GetAttemptedCount returns how many credentials were tried for a host.
func (cp *Checkpoint) GetAttemptedCount(host string, port int, service string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.AttemptedCreds[hostKey(host, port, service)]
}

// RecordAttemptForHost increments the credential attempt count for a host.
func (cp *Checkpoint) RecordAttemptForHost(host string, port int, service string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.AttemptedCreds[hostKey(host, port, service)]++
}

// RecordSuccessForCheckpoint adds a successful credential to the checkpoint.
func (cp *Checkpoint) RecordSuccessForCheckpoint(service, host string, port int, user, password string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.SuccessfulCreds = append(cp.SuccessfulCreds, SuccessEntry{
		Service:  service,
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
	})
}

// Save writes the checkpoint to disk.
func (cp *Checkpoint) Save() error {
	cp.mu.Lock()
	cp.LastSave = time.Now()
	data, err := json.MarshalIndent(cp, "", "  ")
	cp.mu.Unlock()
	if err != nil {
		return fmt.Errorf("marshaling checkpoint: %w", err)
	}

	tmpFile := cp.FilePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("writing checkpoint: %w", err)
	}
	if err := os.Rename(tmpFile, cp.FilePath); err != nil {
		return fmt.Errorf("renaming checkpoint: %w", err)
	}
	return nil
}

// StartPeriodicSave saves the checkpoint periodically until stop is closed.
func (cp *Checkpoint) StartPeriodicSave(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := cp.Save(); err != nil {
					fmt.Printf("[!] Checkpoint save error: %v\n", err)
				}
			case <-stop:
				return
			}
		}
	}()
}
