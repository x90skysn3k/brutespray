package brutespray

import (
	"testing"
	"time"
)

func TestLockoutPolicyEffectiveBudget(t *testing.T) {
	policy := LockoutPolicy{LockoutThreshold: 5, SafeMargin: 1, LockoutWindow: 15 * time.Minute}
	if got := policy.EffectiveBudget(); got != 4 {
		t.Fatalf("budget = %d, want 4", got)
	}
}

func TestLockoutPolicyRejectsUnsafeMargin(t *testing.T) {
	policy := LockoutPolicy{LockoutThreshold: 3, SafeMargin: 3, LockoutWindow: time.Minute}
	if err := policy.Validate(); err == nil {
		t.Fatal("expected invalid policy")
	}
}

func TestLockoutPolicyFromManifest(t *testing.T) {
	policy, err := LockoutPolicyFromManifest(ManifestPolicy{LockoutThreshold: 5, LockoutWindow: "15m", SafeMargin: 1, JitterPercent: 10})
	if err != nil {
		t.Fatalf("LockoutPolicyFromManifest: %v", err)
	}
	if policy.LockoutWindow != 15*time.Minute || policy.JitterPercent != 10 {
		t.Fatalf("policy = %+v", policy)
	}
}
