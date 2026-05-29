package brute

import (
	"testing"

	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
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
