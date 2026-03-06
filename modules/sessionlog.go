package modules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// SessionEntry represents a single event recorded to the session log.
type SessionEntry struct {
	Type      string        `json:"type"` // "attempt", "host_started", "host_completed"
	Host      string        `json:"host"`
	Port      int           `json:"port"`
	Service   string        `json:"service"`
	User      string        `json:"user,omitempty"`
	Password  string        `json:"password,omitempty"`
	Success   bool          `json:"success,omitempty"`
	Connected bool          `json:"connected,omitempty"`
	Retrying  bool          `json:"retrying,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	// Host started fields
	Threads int `json:"threads,omitempty"`
	// Host completion fields
	TotalAttempts int64   `json:"total_attempts,omitempty"`
	SuccessRate   float64 `json:"success_rate,omitempty"`
	AvgResponseMs float64 `json:"avg_response_ms,omitempty"`
}

// SessionLog manages append-only JSONL logging of attempt results.
type SessionLog struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
}

// NewSessionLog creates a new session log writer.
func NewSessionLog(filePath string) (*SessionLog, error) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening session log: %w", err)
	}
	return &SessionLog{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// Write appends a single entry to the session log.
// Errors are logged to stderr but do not block workers.
func (sl *SessionLog) Write(entry SessionEntry) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if err := sl.encoder.Encode(entry); err != nil {
		fmt.Fprintf(os.Stderr, "[!] session log write error: %v\n", err)
	}
}

// Close closes the underlying file.
func (sl *SessionLog) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.file != nil {
		return sl.file.Close()
	}
	return nil
}

// SessionLogPath derives the session log path from a checkpoint file path.
func SessionLogPath(checkpointPath string) string {
	if strings.HasSuffix(checkpointPath, ".json") {
		return strings.TrimSuffix(checkpointPath, ".json") + ".jsonl"
	}
	return checkpointPath + ".jsonl"
}

// LoadSessionLog reads all entries from a JSONL session log file.
func LoadSessionLog(filePath string) ([]SessionEntry, error) {
	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no session log yet
		}
		return nil, fmt.Errorf("reading session log: %w", err)
	}
	defer f.Close()

	var entries []SessionEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry SessionEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}
