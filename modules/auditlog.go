package modules

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AuditEvent is one tamper-evident JSONL audit record.
type AuditEvent struct {
	Type      string            `json:"type"`
	RunID     string            `json:"run_id,omitempty"`
	Sequence  int64             `json:"sequence"`
	Timestamp time.Time         `json:"timestamp"`
	Data      map[string]string `json:"data,omitempty"`
	PrevHash  string            `json:"prev_hash,omitempty"`
	Hash      string            `json:"hash"`
}

// AuditLog writes hash-chained audit events.
type AuditLog struct {
	file     *os.File
	encoder  *json.Encoder
	sequence int64
	prevHash string
	key      []byte
}

// NewAuditLog creates a new owner-readable audit log protected by HMAC-SHA256.
func NewAuditLog(path string, key []byte) (*AuditLog, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("audit HMAC key is required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	return &AuditLog{file: file, encoder: json.NewEncoder(file), key: append([]byte(nil), key...)}, nil
}

// Write appends one event with sequence, timestamp, and hash fields filled.
func (l *AuditLog) Write(event AuditEvent) error {
	if l == nil || l.encoder == nil {
		return fmt.Errorf("audit log is closed")
	}
	l.sequence++
	event.Sequence = l.sequence
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.PrevHash = l.prevHash
	event.Hash = hashAuditEvent(event, l.key)
	if err := l.encoder.Encode(event); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	l.prevHash = event.Hash
	return nil
}

// Close closes the underlying audit log file.
func (l *AuditLog) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	for i := range l.key {
		l.key[i] = 0
	}
	l.key = nil
	l.file = nil
	l.encoder = nil
	return err
}

// VerifyAuditLog verifies every event HMAC and previous-HMAC pointer.
func VerifyAuditLog(path string, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("audit HMAC key is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	var prev string
	var sequence int64
	for scanner.Scan() {
		sequence++
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("event %d invalid JSON: %w", sequence, err)
		}
		if event.Sequence != sequence {
			return fmt.Errorf("event %d sequence mismatch: got %d", sequence, event.Sequence)
		}
		if event.PrevHash != prev {
			return fmt.Errorf("event %d previous hash mismatch", sequence)
		}
		want := hashAuditEvent(event, key)
		if event.Hash != want {
			return fmt.Errorf("event %d hash mismatch", sequence)
		}
		prev = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}
	return nil
}

func hashAuditEvent(event AuditEvent, key []byte) string {
	event.Hash = ""
	data, _ := json.Marshal(event)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
