package brutespray

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// EngagementManifest captures optional run metadata, scope, policy, and evidence defaults.
type EngagementManifest struct {
	Engagement EngagementMetadata `yaml:"engagement" json:"engagement"`
	Scope      ScopeConfig        `yaml:"scope" json:"scope"`
	Policy     ManifestPolicy     `yaml:"policy" json:"policy"`
	Evidence   ManifestEvidence   `yaml:"evidence" json:"evidence"`
}

// EngagementMetadata identifies the authorized assessment context for a run.
type EngagementMetadata struct {
	ID               string `yaml:"id" json:"id"`
	Customer         string `yaml:"customer" json:"customer"`
	Operator         string `yaml:"operator" json:"operator"`
	AuthorizationRef string `yaml:"authorization_ref" json:"authorization_ref"`
}

// ScopeConfig contains allow/deny target scope controls.
type ScopeConfig struct {
	Allow            ScopeSet `yaml:"allow" json:"allow"`
	Deny             ScopeSet `yaml:"deny" json:"deny"`
	RequireInterface string   `yaml:"require_interface" json:"require_interface"`
}

// ScopeSet lists target scope selectors.
type ScopeSet struct {
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
	Hosts []string `yaml:"hosts" json:"hosts"`
}

// ManifestPolicy is the YAML-facing policy shape. Execution converts this into concrete scheduler policy.
type ManifestPolicy struct {
	LockoutThreshold int    `yaml:"lockout_threshold" json:"lockout_threshold"`
	LockoutWindow    string `yaml:"lockout_window" json:"lockout_window"`
	SafeMargin       int    `yaml:"safe_margin" json:"safe_margin"`
	JitterPercent    int    `yaml:"jitter_percent" json:"jitter_percent"`
}

// ManifestEvidence configures default evidence handling from YAML.
type ManifestEvidence struct {
	Mode string `yaml:"mode" json:"mode"`
}

// LoadEngagementManifest loads an optional engagement manifest from disk.
func LoadEngagementManifest(path string) (EngagementManifest, error) {
	if path == "" {
		return EngagementManifest{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return EngagementManifest{}, fmt.Errorf("reading engagement manifest: %w", err)
	}
	var manifest EngagementManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return EngagementManifest{}, fmt.Errorf("parsing engagement manifest: %w", err)
	}
	return manifest, manifest.Validate()
}

// Validate catches ambiguous engagement metadata before execution.
func (m EngagementManifest) Validate() error {
	if m.Engagement.ID == "" && (m.Engagement.Customer != "" || m.Engagement.Operator != "" || m.Engagement.AuthorizationRef != "") {
		return fmt.Errorf("engagement id is required when engagement metadata is provided")
	}
	return nil
}
