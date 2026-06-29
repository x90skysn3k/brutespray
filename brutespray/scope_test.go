package brutespray

import "testing"

func TestScopeDenyOverridesAllow(t *testing.T) {
	matcher, err := NewScopeMatcher(ScopeConfig{
		Allow: ScopeSet{CIDRs: []string{"10.0.0.0/24"}},
		Deny:  ScopeSet{Hosts: []string{"10.0.0.13"}},
	})
	if err != nil {
		t.Fatalf("NewScopeMatcher: %v", err)
	}

	allowed, reason := matcher.Allowed("10.0.0.12")
	if !allowed || reason != "allowed" {
		t.Fatalf("10.0.0.12 allowed=%v reason=%q", allowed, reason)
	}

	allowed, reason = matcher.Allowed("10.0.0.13")
	if allowed || reason != "denied by host" {
		t.Fatalf("10.0.0.13 allowed=%v reason=%q", allowed, reason)
	}
}

func TestScopeRejectsOutsideAllowCIDR(t *testing.T) {
	matcher, err := NewScopeMatcher(ScopeConfig{Allow: ScopeSet{CIDRs: []string{"10.0.0.0/24"}}})
	if err != nil {
		t.Fatalf("NewScopeMatcher: %v", err)
	}
	allowed, reason := matcher.Allowed("10.0.1.10")
	if allowed || reason != "outside allow scope" {
		t.Fatalf("10.0.1.10 allowed=%v reason=%q", allowed, reason)
	}
}

func TestScopeAllowsAllWhenNoAllowSet(t *testing.T) {
	matcher, err := NewScopeMatcher(ScopeConfig{})
	if err != nil {
		t.Fatalf("NewScopeMatcher: %v", err)
	}
	allowed, reason := matcher.Allowed("203.0.113.10")
	if !allowed || reason != "allowed" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}
