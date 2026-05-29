package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBadKeysPlanCoversBundle(t *testing.T) {
	bundle, err := badkeys.Load()
	if err != nil {
		t.Fatalf("badkeys.Load: %v", err)
	}
	plan := PlanBadKeyAttempts(bundle, "")
	if len(plan) != len(bundle) {
		t.Fatalf("plan size = %d, bundle = %d", len(plan), len(bundle))
	}
	for _, a := range plan {
		if a.Username == "" {
			t.Fatalf("attempt missing username: %+v", a)
		}
	}
}

func TestBadKeysPlanRespectsExplicitUser(t *testing.T) {
	bundle, err := badkeys.Load()
	if err != nil {
		t.Fatalf("badkeys.Load: %v", err)
	}
	plan := PlanBadKeyAttempts(bundle, "admin")
	for _, a := range plan {
		if a.Username != "admin" {
			t.Fatalf("explicit username override failed: %s", a.Username)
		}
	}
}

// TestAttemptBadKeyReturnsConnectionFailureOnBadPEM verifies that a corrupt
// PEM blob (which triggers a parse error before any network I/O) causes
// attemptBadKey to return ConnectionSuccess=false.  Prior to the fix the
// function returned ConnectionSuccess=true, which incorrectly credited the
// circuit-breaker and broke the retry logic.
func TestAttemptBadKeyReturnsConnectionFailureOnBadPEM(t *testing.T) {
	cm, err := modules.NewConnectionManager("", 5*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	badEntry := badkeys.Entry{
		File:     "test-invalid.pem",
		Username: "root",
		PEM:      []byte("not a valid PEM key"),
	}

	r := attemptBadKey("127.0.0.1", 22, "root", badEntry, 5*time.Second, cm)
	if r == nil {
		t.Fatal("attemptBadKey returned nil")
	}
	if r.ConnectionSuccess {
		t.Error("expected ConnectionSuccess=false for bad PEM, got true")
	}
	if r.Error == nil {
		t.Error("expected non-nil Error for bad PEM, got nil")
	}
	if r.AuthSuccess {
		t.Error("expected AuthSuccess=false for bad PEM, got true")
	}
}
