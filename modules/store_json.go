package modules

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// JSONStore is an append-only JSONL workspace store.
type JSONStore struct {
	root string
	mu   sync.Mutex
}

// NewJSONStore creates a JSON-backed store rooted at dir.
func NewJSONStore(dir string) (*JSONStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating store: %w", err)
	}
	return &JSONStore{root: dir}, nil
}

// CreateRun creates a run directory and run metadata file.
func (s *JSONStore) CreateRun(run StoreRun) (string, error) {
	if run.ID == "" {
		run.ID = newStoreID()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	dir, err := s.runDir(run.ID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating run: %w", err)
	}
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("writing run: %w", err)
	}
	return run.ID, nil
}

// RecordTarget appends a target record.
func (s *JSONStore) RecordTarget(runID string, target StoreTarget) error {
	return s.appendJSONL(runID, "targets.jsonl", target)
}

// RecordAttempt appends an attempt record.
func (s *JSONStore) RecordAttempt(runID string, attempt StoreAttempt) error {
	return s.appendJSONL(runID, "attempts.jsonl", attempt)
}

// RecordFinding appends a finding record.
func (s *JSONStore) RecordFinding(runID string, finding StoreFinding) error {
	return s.appendJSONL(runID, "findings.jsonl", finding)
}

// LoadRun loads a complete run snapshot.
func (s *JSONStore) LoadRun(runID string) (StoreSnapshot, error) {
	dir, err := s.runDir(runID)
	if err != nil {
		return StoreSnapshot{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return StoreSnapshot{}, err
	}
	var snapshot StoreSnapshot
	if err := json.Unmarshal(data, &snapshot.Run); err != nil {
		return StoreSnapshot{}, err
	}
	if err := readJSONL(filepath.Join(dir, "targets.jsonl"), &snapshot.Targets); err != nil {
		return StoreSnapshot{}, err
	}
	if err := readJSONL(filepath.Join(dir, "attempts.jsonl"), &snapshot.Attempts); err != nil {
		return StoreSnapshot{}, err
	}
	if err := readJSONL(filepath.Join(dir, "findings.jsonl"), &snapshot.Findings); err != nil {
		return StoreSnapshot{}, err
	}
	return snapshot, nil
}

// Close closes the store. JSONStore keeps no open handles.
func (s *JSONStore) Close() error { return nil }

func (s *JSONStore) appendJSONL(runID string, name string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.runDir(runID)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(value)
}

func (s *JSONStore) runDir(runID string) (string, error) {
	if !validStoreID(runID) {
		return "", fmt.Errorf("invalid run id %q", runID)
	}
	return filepath.Join(s.root, runID), nil
}

func validStoreID(runID string) bool {
	if runID == "" || filepath.Base(runID) != runID {
		return false
	}
	for _, r := range runID {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func readJSONL[T any](path string, out *[]T) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var value T
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			return err
		}
		*out = append(*out, value)
	}
	return scanner.Err()
}

func newStoreID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	return "run-" + hex.EncodeToString(b[:])
}
