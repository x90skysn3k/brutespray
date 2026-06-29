package brutespray

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEngagementManifestParsesScopePolicyAndEvidence(t *testing.T) {
	input := []byte(`
engagement:
  id: acme-q3
  customer: Acme
  operator: syoung
  authorization_ref: ROE-123
scope:
  allow:
    cidrs: ["10.0.0.0/24"]
  deny:
    hosts: ["10.0.0.13"]
  require_interface: tun0
policy:
  lockout_threshold: 5
  lockout_window: 15m
  safe_margin: 1
evidence:
  mode: redacted
`)
	var manifest EngagementManifest
	if err := yaml.Unmarshal(input, &manifest); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if manifest.Engagement.ID != "acme-q3" {
		t.Fatalf("engagement id = %q", manifest.Engagement.ID)
	}
	if manifest.Scope.RequireInterface != "tun0" {
		t.Fatalf("require interface = %q", manifest.Scope.RequireInterface)
	}
	if manifest.Policy.LockoutThreshold != 5 {
		t.Fatalf("threshold = %d", manifest.Policy.LockoutThreshold)
	}
	if manifest.Policy.LockoutWindow != "15m" {
		t.Fatalf("window = %q", manifest.Policy.LockoutWindow)
	}
	if manifest.Evidence.Mode != "redacted" {
		t.Fatalf("evidence mode = %q", manifest.Evidence.Mode)
	}
}

func TestEngagementManifestValidateRequiresIDWhenMetadataPresent(t *testing.T) {
	manifest := EngagementManifest{Engagement: EngagementMetadata{Customer: "Acme"}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected validation error for missing engagement id")
	}
}
