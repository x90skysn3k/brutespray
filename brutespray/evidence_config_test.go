package brutespray

import (
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestConfigureEvidenceFromManifest(t *testing.T) {
	orig := modules.GetEvidenceConfig()
	defer modules.SetEvidenceConfig(orig)

	manifest := EngagementManifest{Evidence: ManifestEvidence{Mode: "redacted"}}
	if err := configureEvidenceFromManifest(manifest); err != nil {
		t.Fatalf("configureEvidenceFromManifest: %v", err)
	}
	if got := modules.GetEvidenceConfig().Mode; got != modules.EvidenceRedacted {
		t.Fatalf("evidence mode = %q", got)
	}
}

func TestConfigureEvidenceFromManifestRequiresHashKey(t *testing.T) {
	manifest := EngagementManifest{Evidence: ManifestEvidence{Mode: "hash"}}
	if err := configureEvidenceFromManifest(manifest); err == nil {
		t.Fatal("expected hash mode without hmac_key to fail")
	}
}

func TestConfigureEvidenceFromManifestUsesHashKey(t *testing.T) {
	orig := modules.GetEvidenceConfig()
	defer modules.SetEvidenceConfig(orig)

	manifest := EngagementManifest{Evidence: ManifestEvidence{Mode: "hash", HMACKey: "engagement-key"}}
	if err := configureEvidenceFromManifest(manifest); err != nil {
		t.Fatalf("configureEvidenceFromManifest: %v", err)
	}
	cfg := modules.GetEvidenceConfig()
	if cfg.Mode != modules.EvidenceHash || string(cfg.HMACKey) != "engagement-key" {
		t.Fatalf("evidence config = %+v", cfg)
	}
}

func TestConfigureEvidenceFromManifestRejectsInvalidMode(t *testing.T) {
	manifest := EngagementManifest{Evidence: ManifestEvidence{Mode: "bogus"}}
	if err := configureEvidenceFromManifest(manifest); err == nil {
		t.Fatal("expected invalid evidence mode to fail")
	}
}
